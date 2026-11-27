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

/// RFC 6637 / RFC 4880 OpenPGP Curve25519 ECDH OID (`1.3.6.1.4.1.3029.1.5.1`) prefixed with length `0x0A`.
const OPENPGP_CURVE25519_ECDH_OID: &[u8; 11] =
    &[0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// Extract a genuine 32-byte X25519 Montgomery `u`-coordinate from an RFC 4880 OpenPGP packet stream
/// containing a Curve25519 ECDH Public-Subkey or Public-Key packet (`OID 1.3.6.1.4.1.3029.1.5.1`,
/// MPI header `0x01 0x07 0x40 <32B u>`). Rejects RSA/Ed25519-only keys cleanly (`FUBUKI-HORDE-02`).
fn extract_openpgp_x25519_subkey(raw: &[u8]) -> Option<[u8; 32]> {
    for idx in 0..raw.len() {
        if raw[idx..].starts_with(OPENPGP_CURVE25519_ECDH_OID) {
            let after_oid = &raw[idx + OPENPGP_CURVE25519_ECDH_OID.len()..];
            // RFC 6637 ECDH MPI encoding for 263-bit (`0x0107`) `0x40 || u[32]`
            if after_oid.len() >= 35
                && after_oid[0] == 0x01
                && after_oid[1] == 0x07
                && after_oid[2] == 0x40
            {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&after_oid[3..35]);
                return Some(pk);
            }
        }
    }
    None
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
    let mut crc_line: Option<&str> = None;
    let mut passed_headers = false;
    for line in inner.lines().skip(1) {
        let trimmed = line.trim();
        if !passed_headers {
            if trimmed.is_empty() {
                passed_headers = true;
            }
            continue;
        }
        if let Some(crc_b64) = trimmed.strip_prefix('=') {
            crc_line = Some(crc_b64.trim());
            break;
        }
        body.push_str(trimmed);
    }

    // Fallback when inline armor had no blank header separator line.
    if body.is_empty() {
        for line in inner.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.contains(':') {
                continue;
            }
            if let Some(crc_b64) = trimmed.strip_prefix('=') {
                crc_line = Some(crc_b64.trim());
                break;
            }
            body.push_str(trimmed);
        }
    }

    let raw = B64
        .decode(body.as_bytes())
        .map_err(|e| FubukiError::KeyResolutionError(format!("invalid PGP armor Base64: {e}")))?;

    if let Some(crc_b64) = crc_line {
        let crc_bytes = B64.decode(crc_b64.as_bytes()).map_err(|_| {
            FubukiError::KeyResolutionError("invalid PGP armor CRC24 Base64".into())
        })?;
        if crc_bytes.len() != 3 {
            return Err(FubukiError::KeyResolutionError(
                "invalid PGP armor CRC24 length".into(),
            ));
        }
        let expected_crc = (u32::from(crc_bytes[0]) << 16)
            | (u32::from(crc_bytes[1]) << 8)
            | u32::from(crc_bytes[2]);
        let actual_crc = crc24_rfc4880(&raw);
        if expected_crc != actual_crc {
            return Err(FubukiError::KeyResolutionError(
                "PGP armor RFC 4880 CRC24 checksum mismatch".into(),
            ));
        }
    }

    if raw.len() == 40 && raw.starts_with(ARMOR_MAGIC_V1) {
        if crc_line.is_none() {
            return Err(FubukiError::KeyResolutionError(
                "missing RFC 4880 CRC24 checksum footer on FBKPGP1 armor".into(),
            ));
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&raw[8..40]);
        return Ok(PublicKey::from(pk_bytes));
    }
    if raw.len() == 32 {
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&raw);
        return Ok(PublicKey::from(pk_bytes));
    }
    if let Some(pk_bytes) = extract_openpgp_x25519_subkey(&raw) {
        return Ok(PublicKey::from(pk_bytes));
    }

    Err(FubukiError::KeyResolutionError(
        "OpenPGP block does not contain a Curve25519/X25519 encryption key (RSA/Ed25519-only keys cannot perform X25519 DH)".into(),
    ))
}

/// Parse an in-memory public key literal without touching the filesystem or recursing (`FUBUKI-HORDE-08`).
fn parse_public_key_literal(trimmed: &str) -> FubukiResult<PublicKey> {
    if trimmed.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        return decode_pgp_public_armor(trimmed);
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

    Err(FubukiError::KeyResolutionError(
        "unrecognized public key format (expected PGP X25519 armor, fubuki-pub-v1:<64hex>, 64-hex, or 44-char Base64)".into(),
    ))
}

/// Resolve a public key from a literal token, single-hop file path, or single-hop
/// `./authorized_keys/<user>.{asc,pgp,pub}` entry (`FUBUKI-HORDE-08` — zero recursive file/alias chains).
pub fn parse_public_key_spec(spec: &str, auth_keys_dir: Option<&Path>) -> FubukiResult<PublicKey> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(FubukiError::KeyResolutionError(
            "public key spec cannot be empty".into(),
        ));
    }

    if let Ok(pk) = parse_public_key_literal(trimmed) {
        return Ok(pk);
    }
    if trimmed.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") || trimmed.starts_with(PUB_PREFIX) {
        return parse_public_key_literal(trimmed);
    }

    let candidate = Path::new(trimmed);
    if candidate.is_file() {
        let contents = std::fs::read_to_string(candidate)?;
        return parse_public_key_literal(contents.trim());
    }

    // Single-hop username resolution against Mahajani-style `authorized_keys/` directory.
    if is_safe_username(trimmed) {
        let dir = auth_keys_dir.unwrap_or_else(|| Path::new("authorized_keys"));
        for ext in ["asc", "pgp", "pub"] {
            let key_file = dir.join(format!("{trimmed}.{ext}"));
            if key_file.is_file() {
                let contents = std::fs::read_to_string(&key_file)?;
                return parse_public_key_literal(contents.trim());
            }
        }
    }

    Err(FubukiError::KeyResolutionError(
        "could not resolve public key from spec (not a valid X25519 literal, file, or authorized_keys user)".into(),
    ))
}

/// Parse an in-memory secret key literal without touching the filesystem or recursing (`FUBUKI-HORDE-08`).
fn parse_secret_key_literal(trimmed: &str) -> FubukiResult<StaticSecret> {
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

    if trimmed.len() == 44
        && let Ok(raw) = B64.decode(trimmed.as_bytes())
        && raw.len() == 32
    {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&raw);
        let sk = StaticSecret::from(*bytes);
        bytes.zeroize();
        return Ok(sk);
    }

    Err(FubukiError::KeyResolutionError(
        "invalid secret key format (expected fubuki-sec-v1:<64hex>, 64-hex, 44-char Base64, or key file)".into(),
    ))
}

/// Resolve a Curve25519 secret key from `fubuki-sec-v1:<64hex>`, raw 64-hex, Base64, or a single-hop file path.
pub fn parse_secret_key_spec(spec: &str) -> FubukiResult<StaticSecret> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(FubukiError::KeyResolutionError(
            "secret key spec cannot be empty".into(),
        ));
    }

    if let Ok(sk) = parse_secret_key_literal(trimmed) {
        return Ok(sk);
    }
    if trimmed.starts_with(SEC_PREFIX) {
        return parse_secret_key_literal(trimmed);
    }

    let candidate = Path::new(trimmed);
    if candidate.is_file() {
        let contents = Zeroizing::new(std::fs::read_to_string(candidate)?);
        return parse_secret_key_literal(contents.trim());
    }

    parse_secret_key_literal(trimmed)
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
/// Rejects low-order / non-contributory challenge points (`FUBUKI-HORDE-07`).
pub fn compute_handshake_token(
    secret: &StaticSecret,
    elligator_repr: &[u8; 32],
) -> FubukiResult<Zeroizing<String>> {
    let eph_u = elligator2_decode(elligator_repr);
    let eph_pk = PublicKey::from(eph_u);
    let shared = secret.diffie_hellman(&eph_pk);
    if !shared.was_contributory() {
        return Err(FubukiError::KeyResolutionError(
            "non-contributory low-order X25519 challenge representative".into(),
        ));
    }
    Ok(Zeroizing::new(format!(
        "{HS_PREFIX}{}",
        hex::encode(shared.as_bytes())
    )))
}

/// Compute the sender's shared secret bytes for `recipient_pub` given ephemeral `eph_secret`.
/// Rejects low-order / non-contributory recipient public keys (`FUBUKI-HORDE-07`).
pub fn compute_sender_handshake(
    eph_secret: &StaticSecret,
    recipient_pub: &PublicKey,
) -> FubukiResult<Zeroizing<[u8; 32]>> {
    let shared = eph_secret.diffie_hellman(recipient_pub);
    if !shared.was_contributory() {
        return Err(FubukiError::KeyResolutionError(
            "non-contributory low-order X25519 recipient public key".into(),
        ));
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
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
