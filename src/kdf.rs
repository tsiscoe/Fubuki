//! Domain-separated key hierarchy using `Argon2id` and keyed `BLAKE3` with deterministic
//! `ZeroizeOnDrop` scrubbing across Passphrase, `Mahajani`-style Pubkey Handshake, and Hybrid
//! `Passphrase + Handshake` authentication modalities.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{FubukiError, FubukiResult};

/// Active key-derivation authentication modality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthModality {
    /// Traditional knowledge-factor passphrase only.
    Passphrase,
    /// Zero-password `Mahajani`-style deterministic Curve25519 `Elligator2` handshake response.
    PubkeyHandshake,
    /// Two-factor hybrid (`Passphrase + Pubkey Handshake`).
    HybridPassphraseHandshake,
}

impl AuthModality {
    /// Compact UI badge string for CLI/TUI telemetry.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Passphrase => "PASSPHRASE",
            Self::PubkeyHandshake => "PUBKEY HANDSHAKE (HUNDI)",
            Self::HybridPassphraseHandshake => "HYBRID (PASS + HANDSHAKE)",
        }
    }
}

/// Argon2id stretching profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfProfile {
    /// Memory size in KiB (production default: 65,536 KiB = 64 MiB).
    pub m_kib: u32,
    /// Number of iterations (production default: 3).
    pub t_cost: u32,
    /// Parallelism lanes (production default: 4).
    pub p_cost: u32,
}

impl Default for KdfProfile {
    fn default() -> Self {
        Self::production()
    }
}

impl KdfProfile {
    /// Production Argon2id floor (`m = 64 MiB`, `t = 3`, `p = 4`).
    pub const fn production() -> Self {
        Self {
            m_kib: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }

    /// Lightweight Argon2id profile (`m = 4 MiB`, `t = 1`, `p = 1`) for fast tests and pipelines.
    pub const fn fast() -> Self {
        Self {
            m_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// Human-readable label for CLI/TUI telemetry.
    pub fn label(self) -> String {
        format!(
            "Argon2id ({} MiB, t={}, p={})",
            self.m_kib / 1024,
            self.t_cost,
            self.p_cost
        )
    }
}

/// Independent subkeys expanded from Mode B credentials and 64-byte preamble `S_0`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlotKeys {
    /// 256-bit `XChaCha20-Poly1305` block encryption key.
    pub k_enc: [u8; 32],
    /// 256-bit slot header/AAD binding key.
    pub k_hdr: [u8; 32],
    /// 256-bit slot anchor locator key.
    pub k_loc: [u8; 32],
}

/// Derive Mode B `SlotKeys` supporting all three authentication modalities:
/// - `(Some(pw), None)` -> Passphrase only (backward compatible with v0.1.0)
/// - `(None, Some(hs))` -> Pure `Mahajani`-style Pubkey Handshake (`fubuki-hs-v1:<hex>`)
/// - `(Some(pw), Some(hs))` -> Hybrid (`<passphrase>+fubuki-hs-v1:<hex>`)
pub fn derive_slot_keys_flexible(
    passphrase: Option<&[u8]>,
    preamble_s0: &[u8; 64],
    profile: KdfProfile,
    handshake_secret: Option<&[u8; 32]>,
) -> FubukiResult<SlotKeys> {
    let pw = passphrase.filter(|b| !b.is_empty());
    let mut ikm = Zeroizing::new(Vec::new());

    match (pw, handshake_secret) {
        (Some(p), None) => {
            ikm.extend_from_slice(p);
        }
        (None, Some(hs)) => {
            ikm.extend_from_slice(b"fubuki.modality.handshake.v1|");
            ikm.extend_from_slice(hs);
        }
        (Some(p), Some(hs)) => {
            ikm.extend_from_slice(b"fubuki.modality.hybrid.v1|");
            ikm.extend_from_slice(p);
            ikm.push(b'|');
            ikm.extend_from_slice(hs);
        }
        (None, None) => {
            return Err(FubukiError::KeyResolutionError(
                "at least a passphrase or pubkey handshake secret is required".to_string(),
            ));
        }
    }

    let params = Params::new(profile.m_kib, profile.t_cost, profile.p_cost, Some(32))
        .map_err(|e| FubukiError::KeyResolutionError(format!("invalid Argon2id params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(&ikm, preamble_s0, &mut *master)
        .map_err(|e| FubukiError::KeyResolutionError(format!("Argon2id derivation failed: {e}")))?;

    if let Some(hs) = handshake_secret {
        let mut mix = blake3::Hasher::new_keyed(&master);
        mix.update(b"fubuki.hybrid.x25519.v1");
        mix.update(hs);
        *master = *mix.finalize().as_bytes();
    }

    let k_enc: [u8; 32] = *blake3::keyed_hash(&master, b"fubuki.kdf.enc.v1").as_bytes();
    let k_hdr: [u8; 32] = *blake3::keyed_hash(&master, b"fubuki.kdf.hdr.v1").as_bytes();
    let k_loc: [u8; 32] = *blake3::keyed_hash(&master, b"fubuki.kdf.loc.v1").as_bytes();

    Ok(SlotKeys {
        k_enc,
        k_hdr,
        k_loc,
    })
}

/// Compatibility wrapper for passphrase-anchored derivation (with optional handshake secret).
pub fn derive_slot_keys(
    passphrase: &[u8],
    preamble_s0: &[u8; 64],
    profile: KdfProfile,
    handshake_secret: Option<&[u8; 32]>,
) -> FubukiResult<SlotKeys> {
    derive_slot_keys_flexible(Some(passphrase), preamble_s0, profile, handshake_secret)
}

/// Derive a 256-bit Mode A MAC key directly from a `Mahajani`-style handshake secret and
/// optional hybrid passphrase.
pub fn derive_mode_a_mac_key_from_handshake(
    passphrase: Option<&[u8]>,
    handshake_secret: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("fubuki.mode_a.handshake_mac.v1");
    if let Some(pw) = passphrase.filter(|p| !p.is_empty()) {
        hasher.update(pw);
        hasher.update(b"|");
    }
    hasher.update(handshake_secret);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

/// Normalize a Mode A MAC key from a 64-char hex string, `fubuki-hs-v1:<64hex>` token,
/// `<pass>+fubuki-hs-v1:<64hex>` hybrid token, or arbitrary passphrase string.
///
/// Always scrubs intermediate decoded buffers via `Zeroizing`.
pub fn parse_or_derive_mac_key(raw: &str) -> FubukiResult<Zeroizing<[u8; 32]>> {
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    if trimmed.trim().is_empty() {
        return Err(FubukiError::KeyResolutionError(
            "MAC key material cannot be empty".to_string(),
        ));
    }

    if let Some(hs_hex) = trimmed.trim().strip_prefix("fubuki-hs-v1:") {
        let hs = Zeroizing::new(hex_32(hs_hex.trim())?);
        return Ok(derive_mode_a_mac_key_from_handshake(None, &hs));
    }

    if let Some((pw_part, hs_hex)) = trimmed.rsplit_once("+fubuki-hs-v1:") {
        if pw_part.is_empty() {
            return Err(FubukiError::KeyResolutionError(
                "hybrid Mode A passphrase before '+' cannot be empty".into(),
            ));
        }
        let hs = Zeroizing::new(hex_32(hs_hex.trim())?);
        return Ok(derive_mode_a_mac_key_from_handshake(
            Some(pw_part.as_bytes()),
            &hs,
        ));
    }

    let t = trimmed.trim();
    if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut decoded = Zeroizing::new(
            hex::decode(t)
                .map_err(|e| FubukiError::KeyResolutionError(format!("invalid hex key: {e}")))?,
        );
        if decoded.len() == 32 {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&decoded);
            decoded.zeroize();
            return Ok(key);
        }
    }

    let mut hasher = blake3::Hasher::new_derive_key("fubuki.mode_a.mac_key.v1");
    hasher.update(t.as_bytes());
    let derived = Zeroizing::new(*hasher.finalize().as_bytes());
    Ok(derived)
}

fn hex_32(s: &str) -> FubukiResult<[u8; 32]> {
    if s.len() != 64 {
        return Err(FubukiError::KeyResolutionError(format!(
            "expected 64 hex chars in handshake token, got {}",
            s.len()
        )));
    }
    let decoded = Zeroizing::new(
        hex::decode(s)
            .map_err(|e| FubukiError::KeyResolutionError(format!("invalid hex key: {e}")))?,
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}
