//! Branchless slot anchor resolution, overlap-free dual provisioning, and `XChaCha20-Poly1305`
//! block stride encryption/decryption across Passphrase, `Mahajani` Pubkey Handshake, and Hybrid
//! `Passphrase + Handshake` modalities.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::Utc;
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::elligator::{elligator2_generate_ephemeral, elligator2_matches_secret};
use super::{
    ANCHOR_DATA_CAPACITY, BLOCK_NONCE_SIZE, BLOCK_PLAINTEXT_SIZE, BLOCK_SIZE, BLOCK_TAG_SIZE,
    DEFAULT_B_GUARD, PREAMBLE_SIZE, SLOT_HEADER_SIZE, SLOT_MAGIC, container_byte_len,
    validate_container_len,
};
use crate::kdf::{KdfProfile, SlotKeys, derive_slot_keys_flexible};
use crate::{FubukiError, FubukiResult};

/// Flag bit indicating slot was provisioned under the 25% decoy block ceiling.
pub const FLAG_DECOY_CEILING: u32 = 0x0000_0001;

/// Maximum rejection-sampling iterations for dual-slot `S_0` anchor separation.
const MAX_DUAL_RESALT_ATTEMPTS: usize = 256;

/// Decrypted view of an unlocked coercion-volume slot.
///
/// Intentionally exposes **only** the unlocked slot's own logical span (`anchor_block`,
/// `block_count`, `payload`) with zero knowledge of any other slot or slack boundary.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockedSlot {
    /// Starting logical block index $\beta_0$.
    pub anchor_block: u64,
    /// Number of contiguous 4 KiB blocks consumed by this slot.
    pub block_count: u32,
    /// Creation timestamp stored inside the authenticated slot descriptor.
    pub created_unix_secs: u64,
    /// Slot flags recorded in the authenticated descriptor.
    pub flags: u32,
    /// Recovered plaintext payload wrapped in `Zeroizing`.
    pub payload: Zeroizing<Vec<u8>>,
}

/// Guard margin `B_guard` preserving tail capacity for multi-block slot anchors.
pub fn compute_guard_blocks(total_blocks: u64) -> u64 {
    if total_blocks >= 256 {
        DEFAULT_B_GUARD
    } else {
        (total_blocks / 16).max(1)
    }
}

/// Compute starting block index $\beta_0 = \text{LE64}(\text{BLAKE3}_{K_{\text{loc}}}(\text{"fubuki.slot.anchor.v1"})) \bmod (B - B_{\text{guard}})$
/// using one universal branchless formula.
pub fn compute_anchor_block(k_loc: &[u8; 32], total_blocks: u64) -> FubukiResult<u64> {
    let b_guard = compute_guard_blocks(total_blocks);
    if total_blocks <= b_guard {
        return Err(FubukiError::ContainerGeometryError(
            "total_blocks must exceed B_guard".into(),
        ));
    }
    let digest = blake3::keyed_hash(k_loc, b"fubuki.slot.anchor.v1");
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&digest.as_bytes()[0..8]);
    let val = u64::from_le_bytes(raw);
    Ok(val % (total_blocks - b_guard))
}

/// Compute contiguous block count required to store `payload_len` bytes across 4 KiB stride blocks.
pub fn blocks_needed_for_payload(payload_len: usize) -> usize {
    if payload_len <= ANCHOR_DATA_CAPACITY {
        1
    } else {
        let remaining = payload_len - ANCHOR_DATA_CAPACITY;
        1 + remaining.div_ceil(BLOCK_PLAINTEXT_SIZE)
    }
}

/// Sample an ephemeral Curve25519 keypair paired with a uniform 64-byte preamble
/// `S_0 = Elligator2(R)[32] || Salt_256[32]`.
pub fn generate_ephemeral_preamble() -> (StaticSecret, [u8; PREAMBLE_SIZE]) {
    let mut rng = OsRng;
    let (sk, repr) = elligator2_generate_ephemeral(&mut rng);

    let mut s0 = [0u8; PREAMBLE_SIZE];
    s0[0..32].copy_from_slice(&repr);
    rng.fill_bytes(&mut s0[32..64]);
    (sk, s0)
}

/// Sample a uniform 64-byte preamble `S_0` directly from `OsRng` (`FUBUKI-HORDE-04`).
pub fn generate_uniform_preamble() -> [u8; PREAMBLE_SIZE] {
    let mut s0 = [0u8; PREAMBLE_SIZE];
    OsRng.fill_bytes(&mut s0);
    s0
}

/// Initialize a uniform CSPRNG container (`64 + total_blocks * 4096` bytes) without binding any
/// slot passphrases yet.
pub fn init_volume_bytes(total_blocks: u64) -> FubukiResult<Vec<u8>> {
    if total_blocks < 8 {
        return Err(FubukiError::ContainerGeometryError(
            "coercion volume requires at least 8 blocks (32 KiB)".into(),
        ));
    }
    let byte_len = container_byte_len(total_blocks)?;
    let mut buf = vec![0u8; byte_len];
    let mut rng = OsRng;
    rng.fill_bytes(&mut buf);

    let s0 = generate_uniform_preamble();
    buf[0..PREAMBLE_SIZE].copy_from_slice(&s0);
    Ok(buf)
}

/// Initialize a container with rejection-sampled preamble `S_0` guaranteeing disjoint anchors for
/// dual passphrase slots:
/// - Slot 0 (`duress_pass`) lands strictly inside `[0, decoy_max_blocks - b_guard]`
/// - Slot 1 (`sov_pass`) lands strictly inside `[decoy_max_blocks, total_blocks - b_guard]`
pub fn init_volume_dual_bytes(
    total_blocks: u64,
    decoy_max_blocks: Option<u64>,
    duress_pass: &[u8],
    sov_pass: &[u8],
    profile: KdfProfile,
) -> FubukiResult<(Vec<u8>, u64, u64)> {
    if total_blocks < 16 {
        return Err(FubukiError::ContainerGeometryError(
            "dual-slot coercion volume requires at least 16 blocks".into(),
        ));
    }
    let b_guard = compute_guard_blocks(total_blocks);
    let decoy_ceiling = decoy_max_blocks
        .unwrap_or(total_blocks / 4)
        .clamp(b_guard + 1, total_blocks / 2);

    if decoy_ceiling <= b_guard || total_blocks - decoy_ceiling <= b_guard {
        return Err(FubukiError::ContainerGeometryError(
            "decoy partition leaves insufficient guard margin for dual slots".into(),
        ));
    }

    for _ in 0..MAX_DUAL_RESALT_ATTEMPTS {
        let s0 = generate_uniform_preamble();
        let k_duress = derive_slot_keys_flexible(Some(duress_pass), &s0, profile, None)?;
        let beta_duress = compute_anchor_block(&k_duress.k_loc, total_blocks)?;
        if beta_duress + b_guard > decoy_ceiling {
            continue;
        }

        let k_sov = derive_slot_keys_flexible(Some(sov_pass), &s0, profile, None)?;
        let beta_sov = compute_anchor_block(&k_sov.k_loc, total_blocks)?;
        if beta_sov < decoy_ceiling || beta_sov + b_guard > total_blocks {
            continue;
        }

        let byte_len = container_byte_len(total_blocks)?;
        let mut buf = vec![0u8; byte_len];
        let mut rng = OsRng;
        rng.fill_bytes(&mut buf);
        buf[0..PREAMBLE_SIZE].copy_from_slice(&s0);
        return Ok((buf, beta_duress, beta_sov));
    }

    Err(FubukiError::SlotOverlapExhausted)
}

/// Provisioned dual-pubkey volume output containing the uniform container, one-time
/// ephemeral sealing secret, and disjoint decoy/sovereign anchor block indices.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DualPubkeyVolume {
    #[zeroize(skip)]
    pub container: Vec<u8>,
    pub ephemeral_secret: Zeroizing<[u8; 32]>,
    pub duress_anchor: u64,
    pub sov_anchor: u64,
}

/// Initialize a container with rejection-sampled `S_0 = Elligator2(R) || Salt_256` guaranteeing
/// disjoint anchors for dual `Mahajani`-style public keys (`duress_pub` vs `sov_pub`, each
/// optionally paired with a hybrid passphrase).
pub fn init_volume_dual_pubkeys_bytes(
    total_blocks: u64,
    decoy_max_blocks: Option<u64>,
    duress_pub: &PublicKey,
    sov_pub: &PublicKey,
    duress_pass: Option<&[u8]>,
    sov_pass: Option<&[u8]>,
    profile: KdfProfile,
) -> FubukiResult<DualPubkeyVolume> {
    init_volume_dual_pubkeys_with_spans(
        total_blocks,
        decoy_max_blocks,
        duress_pub,
        sov_pub,
        duress_pass,
        sov_pass,
        None,
        None,
        profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn init_volume_dual_pubkeys_with_spans(
    total_blocks: u64,
    decoy_max_blocks: Option<u64>,
    duress_pub: &PublicKey,
    sov_pub: &PublicKey,
    duress_pass: Option<&[u8]>,
    sov_pass: Option<&[u8]>,
    duress_min_blocks: Option<u64>,
    sov_min_blocks: Option<u64>,
    profile: KdfProfile,
) -> FubukiResult<DualPubkeyVolume> {
    if total_blocks < 16 {
        return Err(FubukiError::ContainerGeometryError(
            "dual-slot coercion volume requires at least 16 blocks".into(),
        ));
    }
    let b_guard = compute_guard_blocks(total_blocks);
    let decoy_ceiling = decoy_max_blocks
        .unwrap_or(total_blocks / 4)
        .clamp(b_guard + 1, total_blocks / 2);

    let d_span = duress_min_blocks.unwrap_or(b_guard).max(1);
    let s_span = sov_min_blocks.unwrap_or(b_guard).max(1);

    if decoy_ceiling <= b_guard || total_blocks - decoy_ceiling <= b_guard {
        return Err(FubukiError::ContainerGeometryError(
            "decoy partition leaves insufficient guard margin for dual slots".into(),
        ));
    }
    if d_span > decoy_ceiling {
        return Err(FubukiError::PayloadExceedsCapacity {
            needed_blocks: d_span as usize,
            max_blocks: decoy_ceiling as usize,
        });
    }
    if s_span > total_blocks - decoy_ceiling {
        return Err(FubukiError::PayloadExceedsCapacity {
            needed_blocks: s_span as usize,
            max_blocks: (total_blocks - decoy_ceiling) as usize,
        });
    }

    for _ in 0..MAX_DUAL_RESALT_ATTEMPTS {
        let (sk_eph, s0) = generate_ephemeral_preamble();
        let dh_duress = sk_eph.diffie_hellman(duress_pub);
        if !dh_duress.was_contributory() {
            return Err(FubukiError::KeyResolutionError(
                "non-contributory low-order X25519 duress public key".into(),
            ));
        }
        let hs_duress = Zeroizing::new(*dh_duress.as_bytes());
        let k_duress = derive_slot_keys_flexible(duress_pass, &s0, profile, Some(&*hs_duress))?;
        let beta_duress = compute_anchor_block(&k_duress.k_loc, total_blocks)?;
        if beta_duress + d_span > decoy_ceiling {
            continue;
        }

        let dh_sov = sk_eph.diffie_hellman(sov_pub);
        if !dh_sov.was_contributory() {
            return Err(FubukiError::KeyResolutionError(
                "non-contributory low-order X25519 sovereign public key".into(),
            ));
        }
        let hs_sov = Zeroizing::new(*dh_sov.as_bytes());
        let k_sov = derive_slot_keys_flexible(sov_pass, &s0, profile, Some(&*hs_sov))?;
        let beta_sov = compute_anchor_block(&k_sov.k_loc, total_blocks)?;
        if beta_sov < decoy_ceiling || beta_sov + s_span > total_blocks {
            continue;
        }

        let byte_len = container_byte_len(total_blocks)?;
        let mut buf = vec![0u8; byte_len];
        let mut rng = OsRng;
        rng.fill_bytes(&mut buf);
        buf[0..PREAMBLE_SIZE].copy_from_slice(&s0);
        return Ok(DualPubkeyVolume {
            container: buf,
            ephemeral_secret: Zeroizing::new(sk_eph.to_bytes()),
            duress_anchor: beta_duress,
            sov_anchor: beta_sov,
        });
    }

    Err(FubukiError::SlotOverlapExhausted)
}

/// Output of one-shot `init_and_seal_dual_pubkeys_bytes` where the ephemeral sealing secret
/// is generated, applied to both slots, and immediately zeroized strictly inside RAM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DualSealedVolume {
    #[zeroize(skip)]
    pub container: Vec<u8>,
    pub duress_anchor: u64,
    pub duress_blocks: u32,
    pub sov_anchor: u64,
    pub sov_blocks: u32,
}

/// One-shot compound dual-pubkey initialization + sealing:
/// samples a disjoint `S_0`, seals both `duress_payload` (`decoy_mode = true`) and `sov_payload`
/// (`decoy_mode = false`) strictly in RAM, and zeroizes the ephemeral sealing key without ever
/// printing or exporting it.
#[allow(clippy::too_many_arguments)]
pub fn init_and_seal_dual_pubkeys_bytes(
    total_blocks: u64,
    decoy_max_blocks: Option<u64>,
    duress_pub: &PublicKey,
    sov_pub: &PublicKey,
    duress_pass: Option<&[u8]>,
    sov_pass: Option<&[u8]>,
    duress_payload: &[u8],
    sov_payload: &[u8],
    profile: KdfProfile,
) -> FubukiResult<DualSealedVolume> {
    let d_needed = blocks_needed_for_payload(duress_payload.len()) as u64;
    let s_needed = blocks_needed_for_payload(sov_payload.len()) as u64;
    let mut dual = init_volume_dual_pubkeys_with_spans(
        total_blocks,
        decoy_max_blocks,
        duress_pub,
        sov_pub,
        duress_pass,
        sov_pass,
        Some(d_needed),
        Some(s_needed),
        profile,
    )?;

    let mut eph_sk = StaticSecret::from(*dual.ephemeral_secret);
    let mut container = std::mem::take(&mut dual.container);

    let (d_anchor, d_blocks) = seal_volume_for_pubkey_bytes(
        &mut container,
        duress_pub,
        Some(&eph_sk),
        duress_pass,
        duress_payload,
        true,
        profile,
    )?;

    let (s_anchor, s_blocks) = seal_volume_for_pubkey_bytes(
        &mut container,
        sov_pub,
        Some(&eph_sk),
        sov_pass,
        sov_payload,
        false,
        profile,
    )?;

    eph_sk = StaticSecret::from([0u8; 32]);
    drop(eph_sk);
    drop(dual);

    Ok(DualSealedVolume {
        container,
        duress_anchor: d_anchor,
        duress_blocks: d_blocks,
        sov_anchor: s_anchor,
        sov_blocks: s_blocks,
    })
}

fn block_aad(block_idx: u64, k_hdr: &[u8; 32]) -> [u8; 40] {
    let mut aad = [0u8; 40];
    aad[0..8].copy_from_slice(&block_idx.to_le_bytes());
    aad[8..40].copy_from_slice(k_hdr);
    aad
}

fn encrypt_stride_block(
    keys: &SlotKeys,
    block_idx: u64,
    plaintext: &[u8; BLOCK_PLAINTEXT_SIZE],
) -> FubukiResult<[u8; BLOCK_SIZE]> {
    let cipher = XChaCha20Poly1305::new((&keys.k_enc).into());
    let mut nonce_bytes = [0u8; BLOCK_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = block_aad(block_idx, &keys.k_hdr);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| FubukiError::AuthenticationFailed)?;

    if ciphertext.len() != BLOCK_PLAINTEXT_SIZE + BLOCK_TAG_SIZE {
        return Err(FubukiError::ContainerGeometryError(
            "unexpected XChaCha20-Poly1305 ciphertext size".into(),
        ));
    }

    let mut out = [0u8; BLOCK_SIZE];
    out[0..BLOCK_NONCE_SIZE].copy_from_slice(&nonce_bytes);
    out[BLOCK_NONCE_SIZE..BLOCK_SIZE].copy_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_stride_block(
    keys: &SlotKeys,
    block_idx: u64,
    block_bytes: &[u8],
) -> FubukiResult<Zeroizing<[u8; BLOCK_PLAINTEXT_SIZE]>> {
    if block_bytes.len() != BLOCK_SIZE {
        return Err(FubukiError::AuthenticationFailed);
    }

    let cipher = XChaCha20Poly1305::new((&keys.k_enc).into());
    let nonce = XNonce::from_slice(&block_bytes[0..BLOCK_NONCE_SIZE]);
    let aad = block_aad(block_idx, &keys.k_hdr);

    let mut pt_vec = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &block_bytes[BLOCK_NONCE_SIZE..BLOCK_SIZE],
                    aad: &aad,
                },
            )
            .map_err(|_| FubukiError::AuthenticationFailed)?,
    );

    if pt_vec.len() != BLOCK_PLAINTEXT_SIZE {
        return Err(FubukiError::AuthenticationFailed);
    }

    let mut pt = Zeroizing::new([0u8; BLOCK_PLAINTEXT_SIZE]);
    pt.copy_from_slice(&pt_vec);
    pt_vec.zeroize();
    Ok(pt)
}

/// Seal `payload` into `container` under a passphrase-only credential.
pub fn seal_volume_bytes(
    container: &mut [u8],
    passphrase: &[u8],
    payload: &[u8],
    decoy_mode: bool,
    profile: KdfProfile,
) -> FubukiResult<(u64, u32)> {
    seal_volume_with_modality_bytes(
        container,
        Some(passphrase),
        None,
        payload,
        decoy_mode,
        profile,
    )
}

/// Seal `payload` into `container` for a `Mahajani`-style recipient public key.
///
/// When `eph_secret_override` is `Some(sk_eph)`, reuses the container's existing `Elligator2`
/// preamble `S_0[0..32]` (verifying it decodes to `PublicKey::from(sk_eph)` so previously sealed
/// dual-trajectory slots stay intact). When `None`, samples a fresh `(sk_eph, S_0)` preamble.
pub fn seal_volume_for_pubkey_bytes(
    container: &mut [u8],
    recipient_pub: &PublicKey,
    eph_secret_override: Option<&StaticSecret>,
    passphrase: Option<&[u8]>,
    payload: &[u8],
    decoy_mode: bool,
    profile: KdfProfile,
) -> FubukiResult<(u64, u32)> {
    let _total_blocks = validate_container_len(container.len())?;

    let hs = match eph_secret_override {
        Some(sk_eph) => {
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&container[0..32]);
            if !elligator2_matches_secret(&repr, sk_eph) {
                return Err(FubukiError::KeyResolutionError(
                    "ephemeral sealing key does not match container S_0[0..32] Elligator2 preamble"
                        .into(),
                ));
            }
            let dh = sk_eph.diffie_hellman(recipient_pub);
            if !dh.was_contributory() {
                return Err(FubukiError::KeyResolutionError(
                    "non-contributory low-order X25519 recipient public key".into(),
                ));
            }
            Zeroizing::new(*dh.as_bytes())
        }
        None => {
            let (sk_eph, s0) = generate_ephemeral_preamble();
            let dh = sk_eph.diffie_hellman(recipient_pub);
            if !dh.was_contributory() {
                return Err(FubukiError::KeyResolutionError(
                    "non-contributory low-order X25519 recipient public key".into(),
                ));
            }
            container[0..PREAMBLE_SIZE].copy_from_slice(&s0);
            Zeroizing::new(*dh.as_bytes())
        }
    };

    seal_volume_with_modality_bytes(
        container,
        passphrase,
        Some(&*hs),
        payload,
        decoy_mode,
        profile,
    )
}

/// Seal `payload` into `container` using any supported modality `(passphrase, handshake_secret)`.
pub fn seal_volume_with_modality_bytes(
    container: &mut [u8],
    passphrase: Option<&[u8]>,
    handshake_secret: Option<&[u8; 32]>,
    payload: &[u8],
    decoy_mode: bool,
    profile: KdfProfile,
) -> FubukiResult<(u64, u32)> {
    let total_blocks = validate_container_len(container.len())?;
    let mut s0 = [0u8; PREAMBLE_SIZE];
    s0.copy_from_slice(&container[0..PREAMBLE_SIZE]);

    let keys = derive_slot_keys_flexible(passphrase, &s0, profile, handshake_secret)?;
    let anchor = compute_anchor_block(&keys.k_loc, total_blocks)?;
    let needed_blocks = blocks_needed_for_payload(payload.len());

    let decoy_ceiling = (total_blocks as usize / 4).max(1);
    if decoy_mode && needed_blocks > decoy_ceiling {
        return Err(FubukiError::PayloadExceedsCapacity {
            needed_blocks,
            max_blocks: decoy_ceiling,
        });
    }

    if decoy_mode && (anchor as usize + needed_blocks) > decoy_ceiling {
        return Err(FubukiError::PayloadExceedsCapacity {
            needed_blocks,
            max_blocks: decoy_ceiling.saturating_sub(anchor as usize),
        });
    }

    let anchor_usize = anchor as usize;
    if anchor_usize + needed_blocks > total_blocks as usize {
        return Err(FubukiError::PayloadExceedsCapacity {
            needed_blocks,
            max_blocks: (total_blocks as usize).saturating_sub(anchor_usize),
        });
    }

    let block_count_u32 = u32::try_from(needed_blocks)
        .map_err(|_| FubukiError::ContainerGeometryError("block count exceeds u32".into()))?;
    let created_unix_secs = Utc::now().timestamp().max(0) as u64;
    // Never persist decoy/duress indicator bits inside the authenticated descriptor (`FUBUKI-HORDE-03`),
    // preserving strict coercion symmetry between Slot 0 and Slot 1 under forensic inspection.
    let flags: u32 = 0;

    // Anchor block plaintext: 32B internal header + up to 4024B payload + CSPRNG slack padding.
    let mut pt0 = Zeroizing::new([0u8; BLOCK_PLAINTEXT_SIZE]);
    OsRng.fill_bytes(&mut *pt0);
    pt0[0..8].copy_from_slice(&SLOT_MAGIC);
    pt0[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    pt0[16..24].copy_from_slice(&created_unix_secs.to_le_bytes());
    pt0[24..28].copy_from_slice(&block_count_u32.to_le_bytes());
    pt0[28..32].copy_from_slice(&flags.to_le_bytes());

    let head_len = payload.len().min(ANCHOR_DATA_CAPACITY);
    pt0[SLOT_HEADER_SIZE..SLOT_HEADER_SIZE + head_len].copy_from_slice(&payload[..head_len]);
    let enc0 = encrypt_stride_block(&keys, anchor, &pt0)?;
    let off0 = PREAMBLE_SIZE + anchor_usize * BLOCK_SIZE;
    container[off0..off0 + BLOCK_SIZE].copy_from_slice(&enc0);

    let mut offset = head_len;
    for step in 1..needed_blocks {
        let block_idx = anchor + step as u64;
        let mut pt = Zeroizing::new([0u8; BLOCK_PLAINTEXT_SIZE]);
        OsRng.fill_bytes(&mut *pt);
        let take = (payload.len() - offset).min(BLOCK_PLAINTEXT_SIZE);
        pt[..take].copy_from_slice(&payload[offset..offset + take]);
        offset += take;

        let enc = encrypt_stride_block(&keys, block_idx, &pt)?;
        let byte_off = PREAMBLE_SIZE + (anchor_usize + step) * BLOCK_SIZE;
        container[byte_off..byte_off + BLOCK_SIZE].copy_from_slice(&enc);
    }

    Ok((anchor, block_count_u32))
}

/// Constant-time branchless unlock for passphrase-only credentials.
pub fn unlock_volume_bytes(
    container: &[u8],
    passphrase: &[u8],
    profile: KdfProfile,
) -> FubukiResult<UnlockedSlot> {
    unlock_volume_with_modality_bytes(container, Some(passphrase), None, profile)
}

/// Constant-time branchless unlock executing the identical derivation and Poly1305 verification
/// path across Passphrase, Pubkey Handshake (`fubuki-hs-v1`), and Hybrid modalities.
pub fn unlock_volume_with_modality_bytes(
    container: &[u8],
    passphrase: Option<&[u8]>,
    handshake_secret: Option<&[u8; 32]>,
    profile: KdfProfile,
) -> FubukiResult<UnlockedSlot> {
    let total_blocks = validate_container_len(container.len())?;
    let mut s0 = [0u8; PREAMBLE_SIZE];
    s0.copy_from_slice(&container[0..PREAMBLE_SIZE]);

    let keys = derive_slot_keys_flexible(passphrase, &s0, profile, handshake_secret)?;
    let anchor = compute_anchor_block(&keys.k_loc, total_blocks)?;
    let anchor_usize = anchor as usize;

    let off0 = PREAMBLE_SIZE + anchor_usize * BLOCK_SIZE;
    let pt0 = decrypt_stride_block(&keys, anchor, &container[off0..off0 + BLOCK_SIZE])?;

    // Verify internal descriptor magic strictly AFTER AEAD authentication passes.
    if pt0[0..8].ct_eq(&SLOT_MAGIC).unwrap_u8() != 1 {
        return Err(FubukiError::AuthenticationFailed);
    }

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&pt0[8..16]);
    let payload_len_u64 = u64::from_le_bytes(len_bytes);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&pt0[16..24]);
    let created_unix_secs = u64::from_le_bytes(ts_bytes);

    let mut count_bytes = [0u8; 4];
    count_bytes.copy_from_slice(&pt0[24..28]);
    let block_count = u32::from_le_bytes(count_bytes);

    let mut flag_bytes = [0u8; 4];
    flag_bytes.copy_from_slice(&pt0[28..32]);
    let flags = u32::from_le_bytes(flag_bytes);

    let payload_len =
        usize::try_from(payload_len_u64).map_err(|_| FubukiError::AuthenticationFailed)?;
    let expected_blocks = blocks_needed_for_payload(payload_len);
    if block_count as usize != expected_blocks
        || anchor_usize + expected_blocks > total_blocks as usize
    {
        return Err(FubukiError::AuthenticationFailed);
    }

    let mut out = Zeroizing::new(Vec::with_capacity(payload_len));
    let head_len = payload_len.min(ANCHOR_DATA_CAPACITY);
    out.extend_from_slice(&pt0[SLOT_HEADER_SIZE..SLOT_HEADER_SIZE + head_len]);

    let mut remaining = payload_len - head_len;
    for step in 1..expected_blocks {
        let block_idx = anchor + step as u64;
        let off = PREAMBLE_SIZE + (anchor_usize + step) * BLOCK_SIZE;
        let pt = decrypt_stride_block(&keys, block_idx, &container[off..off + BLOCK_SIZE])?;
        let take = remaining.min(BLOCK_PLAINTEXT_SIZE);
        out.extend_from_slice(&pt[..take]);
        remaining -= take;
    }

    Ok(UnlockedSlot {
        anchor_block: anchor,
        block_count,
        created_unix_secs,
        flags,
        payload: out,
    })
}
