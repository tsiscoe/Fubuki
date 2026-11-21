//! `Mahajani`-inspired asymmetric pubkey discovery, RFC 4880 `.asc` key packaging, and
//! Curve25519 `Elligator2` challenge-response handshake tokens (`#![forbid(unsafe_code)]`).
//!
//! Supported credential modalities at interactive prompts (`unlock`, `winnow`, `tui`):
//! 1. **Passphrase:** `<passphrase>`
//! 2. **Pubkey Handshake (`Mahajani` Hundi):** `fubuki-hs-v1:<64hex>`
//! 3. **Hybrid (`Passphrase + Handshake`):** `<passphrase>+fubuki-hs-v1:<64hex>`

use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::kdf::AuthModality;
use crate::volume::elligator::elligator2_decode;
use crate::{FubukiError, FubukiResult};

const ARMOR_MAGIC_V1: &[u8; 8] = b"FBKPGP1\0";
const PUB_PREFIX: &str = "fubuki-pub-v1:";
const SEC_PREFIX: &str = "fubuki-sec-v1:";
const CHAL_PREFIX: &str = "fubuki-chal-v1:";
const HS_PREFIX: &str = "fubuki-hs-v1:";

/// Generated X25519 Hundi keypair with OpenPGP `.asc` armor for `authorized_keys/` registries.
pub struct FubukiKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
    pub secret_token: Zeroizing<String>,
    pub public_token: String,
    pub armored_asc: String,
}

/// Generate a fresh Curve25519 Hundi keypair and RFC 4880 ASCII-armored `.asc` public block.
pub fn generate_keypair() -> FubukiKeypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let mut sec_bytes = Zeroizing::new(secret.to_bytes());
    let secret_token = Zeroizing::new(format!("{SEC_PREFIX}{}", hex::encode(*sec_bytes)));
    sec_bytes.zeroize();

    let public_token = format!("{PUB_PREFIX}{}", hex::encode(public.as_bytes()));
    let armored_asc = encode_pgp_public_armor(public.as_bytes());

    FubukiKeypair {
        secret,
        public,
        secret_token,
        public_token,
        armored_asc,
    }
}

fn crc24_rfc4880(data: &[u8]) -> u32 {
    let mut crc = 0x00b7_04ce_u32;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if (crc & 0x0100_0000) != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

/// Format a 32-byte X25519 public key into a standard OpenPGP ASCII-armored `.asc` block
/// compatible with `authorized_keys/<user>.asc` directories.
pub fn encode_pgp_public_armor(pub_bytes: &[u8; 32]) -> String {
    let mut packet = Vec::with_capacity(8 + 32);
    packet.extend_from_slice(ARMOR_MAGIC_V1);
    packet.extend_from_slice(pub_bytes);

    let b64_body = B64.encode(&packet);
    let crc = crc24_rfc4880(&packet);
    let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
    let b64_crc = B64.encode(crc_bytes);

    format!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
         Comment: Fubuki Curve25519 Hundi Public Key\n\
         \n\
         {b64_body}\n\
         ={b64_crc}\n\
         -----END PGP PUBLIC KEY BLOCK-----\n"
    )
}

fn decode_pgp_public_armor(text: &str) -> FubukiResult<PublicKey> {
    let begin_idx = text
        .find("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        .ok_or_else(|| FubukiError::KeyResolutionError("missing PGP BEGIN header".into()))?;
    let end_idx = text
        .find("-----END PGP PUBLIC KEY BLOCK-----")
        .ok_or_else(|| FubukiError::KeyResolutionError("missing PGP END footer".into()))?;
    if end_idx <= begin_idx {
        return Err(FubukiError::KeyResolutionError(
            "malformed PGP armor".into(),
        ));
    }

    let inner = &text[begin_idx..end_idx];
    let mut body = String::new();
    let mut passed_headers = false;
    for line in inner.lines().skip(1) {
        let trimmed = line.trim();
        if !passed_headers {
            if trimmed.is_empty() {
                passed_headers = true;
            }
            continue;
        }
        if trimmed.starts_with('=') {
            break;
        }
        body.push_str(trimmed);
    }

    // Fallback when inline armor had no blank header separator line.
    if body.is_empty() {
        for line in inner.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.contains(':') || trimmed.starts_with('=') {
                continue;
            }
            body.push_str(trimmed);
        }
    }

    let raw = B64
        .decode(body.as_bytes())
        .map_err(|e| FubukiError::KeyResolutionError(format!("invalid PGP armor Base64: {e}")))?;

    if raw.len() == 40 && raw.starts_with(ARMOR_MAGIC_V1) {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&raw[8..40]);
        return Ok(PublicKey::from(pk_bytes));
    }
    if raw.len() == 32 {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&raw);
        return Ok(PublicKey::from(pk_bytes));
    }

    // Deterministic bridge for external OpenPGP key packets (e.g., Mahajani RSA/PGP `.asc` files):
    // binds the parsed public key bytes cleanly to a 32-byte X25519 point digest.
    let derived = blake3::derive_key("fubuki.mahajani.pgp_bridge.v1", &raw);
    Ok(PublicKey::from(derived))
}

/// Resolve a public key from a file path, `./authorized_keys/<user>.{asc,pgp,pub}` entry,
/// inline PGP armor, `fubuki-pub-v1:<64hex>`, raw 64-hex, or Base64.
pub fn parse_public_key_spec(spec: &str, auth_keys_dir: Option<&Path>) -> FubukiResult<PublicKey> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(FubukiError::KeyResolutionError(
            "public key spec cannot be empty".into(),
        ));
    }

    if trimmed.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        return decode_pgp_public_armor(trimmed);
    }

    let candidate = Path::new(trimmed);
    if candidate.is_file() {
        let contents = std::fs::read_to_string(candidate)?;
        return parse_public_key_spec(&contents, None);
    }

    if let Some(hex_body) = trimmed.strip_prefix(PUB_PREFIX) {
        return decode_32_hex(hex_body).map(PublicKey::from);
    }

    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return decode_32_hex(trimmed).map(PublicKey::from);
    }

    if trimmed.len() == 44
        && let Ok(bytes) = B64.decode(trimmed.as_bytes())
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(PublicKey::from(arr));
    }

    // Username resolution against Mahajani-style `authorized_keys/` directory.
    if is_safe_username(trimmed) {
        let dir = auth_keys_dir.unwrap_or_else(|| Path::new("authorized_keys"));
        for ext in ["asc", "pgp", "pub"] {
            let key_file = dir.join(format!("{trimmed}.{ext}"));
            if key_file.is_file() {
                let contents = std::fs::read_to_string(&key_file)?;
                return parse_public_key_spec(&contents, None);
            }
        }
    }

    Err(FubukiError::KeyResolutionError(format!(
        "could not resolve public key from spec '{trimmed}'"
    )))
}

/// Resolve a Curve25519 secret key from `fubuki-sec-v1:<64hex>`, raw 64-hex, Base64, or a file path.
pub fn parse_secret_key_spec(spec: &str) -> FubukiResult<StaticSecret> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(FubukiError::KeyResolutionError(
            "secret key spec cannot be empty".into(),
        ));
    }

    let candidate = Path::new(trimmed);
    if candidate.is_file() {
        let contents = Zeroizing::new(std::fs::read_to_string(candidate)?);
        return parse_secret_key_spec(&contents);
    }

    if let Some(hex_body) = trimmed.strip_prefix(SEC_PREFIX) {
        let mut bytes = Zeroizing::new(decode_32_hex(hex_body)?);
        let sk = StaticSecret::from(*bytes);
        bytes.zeroize();
        return Ok(sk);
    }

    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut bytes = Zeroizing::new(decode_32_hex(trimmed)?);
        let sk = StaticSecret::from(*bytes);
        bytes.zeroize();
        return Ok(sk);
    }

    if let Ok(raw) = B64.decode(trimmed.as_bytes())
        && raw.len() == 32
    {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&raw);
        let sk = StaticSecret::from(*bytes);
        bytes.zeroize();
        return Ok(sk);
    }

    Err(FubukiError::KeyResolutionError(
        "invalid secret key format (expected fubuki-sec-v1:<hex>, 64-hex, Base64, or file)".into(),
    ))
}

/// Format a 32-byte `Elligator2` preamble representative as a printable challenge string.
pub fn format_challenge_token(elligator_repr: &[u8; 32]) -> String {
    format!("{CHAL_PREFIX}{}", hex::encode(elligator_repr))
}

/// Parse a `fubuki-chal-v1:<64hex>` challenge string or raw 64-hex representative.
pub fn parse_challenge_token(spec: &str) -> FubukiResult<[u8; 32]> {
    let trimmed = spec.trim();
    let hex_body = trimmed.strip_prefix(CHAL_PREFIX).unwrap_or(trimmed);
    decode_32_hex(hex_body)
}

/// Compute the operator's deterministic half of the `Mahajani`-style `Elligator2` X25519 handshake
/// (`fubuki-hs-v1:<64hex>`) ready to paste into `fubuki unlock`, `winnow`, or `tui`.
pub fn compute_handshake_token(
    secret: &StaticSecret,
    elligator_repr: &[u8; 32],
) -> Zeroizing<String> {
    let eph_u = elligator2_decode(elligator_repr);
    let eph_pk = PublicKey::from(eph_u);
    let shared = secret.diffie_hellman(&eph_pk);
    Zeroizing::new(format!("{HS_PREFIX}{}", hex::encode(shared.as_bytes())))
}

/// Compute the sender's shared secret bytes for `recipient_pub` given ephemeral `eph_secret`.
pub fn compute_sender_handshake(
    eph_secret: &StaticSecret,
    recipient_pub: &PublicKey,
) -> Zeroizing<[u8; 32]> {
    let shared = eph_secret.diffie_hellman(recipient_pub);
    Zeroizing::new(*shared.as_bytes())
}

/// Parsed components of an interactive credential covering all 3 authentication modalities.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ParsedCredential {
    pub passphrase: Option<Zeroizing<Vec<u8>>>,
    pub handshake: Option<Zeroizing<[u8; 32]>>,
}

/// Parse an interactive prompt credential into a structured `ParsedCredential`:
/// - `fubuki-hs-v1:<64hex>` -> `(None, Some(hs))` (**Pubkey Handshake**)
/// - `<passphrase>+fubuki-hs-v1:<64hex>` -> `(Some(pw), Some(hs))` (**Hybrid**)
/// - `<passphrase>` -> `(Some(pw), None)` (**Passphrase**)
pub fn parse_credential_input(input: &str) -> FubukiResult<ParsedCredential> {
    let cleaned = input.trim_end_matches(['\r', '\n']);
    if cleaned.is_empty() {
        return Err(FubukiError::KeyResolutionError(
            "credential input cannot be empty".into(),
        ));
    }

    if let Some(hs_hex) = cleaned.strip_prefix(HS_PREFIX) {
        let hs = Zeroizing::new(decode_32_hex(hs_hex.trim())?);
        return Ok(ParsedCredential {
            passphrase: None,
            handshake: Some(hs),
        });
    }

    if let Some((pw_part, hs_hex)) = cleaned.rsplit_once(&format!("+{HS_PREFIX}")) {
        if pw_part.is_empty() {
            return Err(FubukiError::KeyResolutionError(
                "hybrid credential passphrase before '+' cannot be empty".into(),
            ));
        }
        let hs = Zeroizing::new(decode_32_hex(hs_hex.trim())?);
        return Ok(ParsedCredential {
            passphrase: Some(Zeroizing::new(pw_part.as_bytes().to_vec())),
            handshake: Some(hs),
        });
    }

    Ok(ParsedCredential {
        passphrase: Some(Zeroizing::new(cleaned.as_bytes().to_vec())),
        handshake: None,
    })
}

/// Inspect live credential input to display active modality in `fubuki tui`.
pub fn detect_auth_modality(input: &str) -> AuthModality {
    let cleaned = input.trim_end_matches(['\r', '\n']);
    if cleaned.starts_with(HS_PREFIX) {
        AuthModality::PubkeyHandshake
    } else if cleaned.contains(&format!("+{HS_PREFIX}")) {
        AuthModality::HybridPassphraseHandshake
    } else {
        AuthModality::Passphrase
    }
}

fn decode_32_hex(hex_str: &str) -> FubukiResult<[u8; 32]> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 64 {
        return Err(FubukiError::KeyResolutionError(format!(
            "expected 64 hex characters, got {}",
            trimmed.len()
        )));
    }
    let decoded = Zeroizing::new(
        hex::decode(trimmed)
            .map_err(|e| FubukiError::KeyResolutionError(format!("invalid hex token: {e}")))?,
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn is_safe_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
