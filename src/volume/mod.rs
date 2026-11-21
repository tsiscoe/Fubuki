//! Mode B: Elligator2 Headerless Coercion-Resistant Dual Volumes.
//!
//! Container byte layout (`|V| = 64 + B * 4096`):
//! - Offset `0x0000..0x0040` (`64B`): Uniform preamble `S_0 = Elligator2(R)[32] || Salt_256[32]`.
//! - Offset `0x0040..`: `B` fixed-stride `4096`-byte blocks, each initialized with OS CSPRNG
//!   entropy and selectively overwritten in place by `XChaCha20-Poly1305` ciphertexts.

pub mod elligator;
pub mod fe25519;
pub mod slot;

use crate::{FubukiError, FubukiResult};

/// Uniform preamble length in bytes (`Elligator2(R) || Salt_256`).
pub const PREAMBLE_SIZE: usize = 64;

/// Fixed storage stride per container block (`4 KiB`).
pub const BLOCK_SIZE: usize = 4096;

/// Inline `XChaCha20-Poly1305` nonce width per active block.
pub const BLOCK_NONCE_SIZE: usize = 24;

/// Inline `Poly1305` authentication tag width per active block.
pub const BLOCK_TAG_SIZE: usize = 16;

/// Plaintext payload capacity inside each encrypted 4 KiB block (`4056` bytes).
pub const BLOCK_PLAINTEXT_SIZE: usize = BLOCK_SIZE - BLOCK_NONCE_SIZE - BLOCK_TAG_SIZE;

/// Internal encrypted slot descriptor header size (`32` bytes inside anchor block plaintext).
pub const SLOT_HEADER_SIZE: usize = 32;

/// First-block payload data capacity after the 32-byte encrypted slot descriptor (`4024` bytes).
pub const ANCHOR_DATA_CAPACITY: usize = BLOCK_PLAINTEXT_SIZE - SLOT_HEADER_SIZE;

/// Encrypted slot magic tag (verified strictly AFTER `Poly1305` authentication succeeds).
pub const SLOT_MAGIC: [u8; 8] = *b"FBKSLT01";

/// Default guard span (`16` blocks) reserving tail capacity for slot anchors.
pub const DEFAULT_B_GUARD: u64 = 16;

/// Parse a human-friendly byte size string such as `64M`, `16M`, `256K`, or raw bytes.
pub fn parse_size_spec(spec: &str) -> FubukiResult<usize> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(FubukiError::ContainerGeometryError(
            "size specification cannot be empty".into(),
        ));
    }

    let (num_part, mult) = if let Some(s) = trimmed.strip_suffix(['K', 'k']) {
        (s, 1024usize)
    } else if let Some(s) = trimmed.strip_suffix(['M', 'm']) {
        (s, 1024usize * 1024)
    } else if let Some(s) = trimmed.strip_suffix(['G', 'g']) {
        (s, 1024usize * 1024 * 1024)
    } else {
        (trimmed, 1usize)
    };

    let base: usize = num_part.trim().parse().map_err(|_| {
        FubukiError::ContainerGeometryError(format!("invalid size specification: {spec}"))
    })?;
    base.checked_mul(mult)
        .ok_or_else(|| FubukiError::ContainerGeometryError("size specification overflow".into()))
}

/// Compute container block count `B` from a target byte size (rounded up to at least 8 blocks).
pub fn blocks_for_payload_region(bytes: usize) -> FubukiResult<u64> {
    if bytes == 0 {
        return Err(FubukiError::ContainerGeometryError(
            "container size must be greater than zero".into(),
        ));
    }
    let blocks = bytes.div_ceil(BLOCK_SIZE).max(8);
    Ok(blocks as u64)
}

/// Compute the total byte length of a container holding `total_blocks` 4 KiB blocks.
pub fn container_byte_len(total_blocks: u64) -> FubukiResult<usize> {
    let blocks_usize = usize::try_from(total_blocks)
        .map_err(|_| FubukiError::ContainerGeometryError("block count overflow".into()))?;
    blocks_usize
        .checked_mul(BLOCK_SIZE)
        .and_then(|b| b.checked_add(PREAMBLE_SIZE))
        .ok_or_else(|| FubukiError::ContainerGeometryError("container size overflow".into()))
}

/// Inspect raw container length and return total block count `B`.
pub fn validate_container_len(byte_len: usize) -> FubukiResult<u64> {
    if byte_len < PREAMBLE_SIZE + 8 * BLOCK_SIZE
        || !(byte_len - PREAMBLE_SIZE).is_multiple_of(BLOCK_SIZE)
    {
        return Err(FubukiError::ContainerGeometryError(format!(
            "container byte length {byte_len} is not aligned to 64 + B * 4096 (B >= 8)"
        )));
    }
    Ok(((byte_len - PREAMBLE_SIZE) / BLOCK_SIZE) as u64)
}

pub use slot::{
    DualPubkeyVolume, DualSealedVolume, UnlockedSlot, compute_anchor_block, compute_guard_blocks,
    generate_ephemeral_preamble, init_and_seal_dual_pubkeys_bytes, init_volume_bytes,
    init_volume_dual_bytes, init_volume_dual_pubkeys_bytes, seal_volume_bytes,
    seal_volume_for_pubkey_bytes, seal_volume_with_modality_bytes, unlock_volume_bytes,
    unlock_volume_with_modality_bytes,
};
