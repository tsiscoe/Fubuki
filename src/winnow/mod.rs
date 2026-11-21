//! Mode A: Cipherless Keyed-BLAKE3 Chaffing & Winnowing (`scatter` & `filter`).
//!
//! Wire format (zero magic bytes):
//! - Bytes `0..16`: Uniform 128-bit stream session seed `N_s`.
//! - Remaining bytes: integer multiple of 40-byte tuples `(LE64(blinded_seq) || symbol[16] || mac[16])`.

pub mod filter;
pub mod scatter;

use crate::{FubukiError, FubukiResult};
use subtle::ConstantTimeEq;

/// Byte width of the uniform stream session seed `N_s`.
pub const STREAM_SEED_LEN: usize = 16;

/// Default byte width `b` of each wheat/chaff payload frame `w_i`.
pub const FRAME_WIDTH: usize = 16;

/// Truncated keyed-BLAKE3 MAC tag width `t` in bytes (`128` bits).
pub const MAC_TAG_LEN: usize = 16;

/// Serialized wire tuple length: `8B blinded_seq + 16B symbol + 16B MAC = 40B`.
pub const TUPLE_WIRE_LEN: usize = 8 + FRAME_WIDTH + MAC_TAG_LEN;

/// Domain separation prefix for non-final authentic wheat frames.
pub const DOMAIN_WHEAT: &[u8] = b"fubuki.wheat.v1";

/// Domain separation prefix for the final authenticated end-of-stream (`EOS`) wheat frame.
pub const DOMAIN_WHEAT_EOS: &[u8] = b"fubuki.wheat.eos.v1";

/// Compute the 128-bit keyed-BLAKE3 tag for a wheat symbol `(seq_idx, frame, is_eos)`.
pub fn compute_wheat_mac(
    k_mac: &[u8; 32],
    ns: &[u8; STREAM_SEED_LEN],
    seq_idx: u64,
    frame: &[u8; FRAME_WIDTH],
    is_eos: bool,
) -> [u8; MAC_TAG_LEN] {
    let domain = if is_eos {
        DOMAIN_WHEAT_EOS
    } else {
        DOMAIN_WHEAT
    };
    let mut hasher = blake3::Hasher::new_keyed(k_mac);
    hasher.update(domain);
    hasher.update(ns);
    hasher.update(&seq_idx.to_le_bytes());
    hasher.update(frame);
    let digest = hasher.finalize();
    let mut tag = [0u8; MAC_TAG_LEN];
    tag.copy_from_slice(&digest.as_bytes()[0..MAC_TAG_LEN]);
    tag
}

/// Self-inverse unkeyed blinding of monotonic sequence index `seq_idx` at physical wire slot
/// `slot_idx`: `seq_idx ^ Trunc64(BLAKE3(N_s || LE64(slot_idx)))`.
pub fn blind_sequence_index(ns: &[u8; STREAM_SEED_LEN], slot_idx: u64, seq_idx: u64) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ns);
    hasher.update(&slot_idx.to_le_bytes());
    let digest = hasher.finalize();
    let mut mask = [0u8; 8];
    mask.copy_from_slice(&digest.as_bytes()[0..8]);
    seq_idx ^ u64::from_le_bytes(mask)
}

/// Partition arbitrary-length plaintext into PKCS#7-padded 16-byte frames (`L >= 1` frames).
pub fn pkcs7_chunk_frames(payload: &[u8]) -> Vec<[u8; FRAME_WIDTH]> {
    let full_blocks = payload.len() / FRAME_WIDTH;
    let rem = payload.len() % FRAME_WIDTH;
    let pad_len = (FRAME_WIDTH - rem) as u8;

    let mut frames = Vec::with_capacity(full_blocks + 1);
    let (chunks, _) = payload.as_chunks::<FRAME_WIDTH>();
    for &chunk in chunks {
        frames.push(chunk);
    }

    let mut last_frame = [pad_len; FRAME_WIDTH];
    let tail_start = full_blocks * FRAME_WIDTH;
    if rem > 0 {
        last_frame[..rem].copy_from_slice(&payload[tail_start..]);
    }
    frames.push(last_frame);
    frames
}

/// Validate and strip PKCS#7 padding from the final frame using constant-time byte checks.
pub fn pkcs7_strip_last_frame(last: &[u8; FRAME_WIDTH]) -> FubukiResult<&[u8]> {
    let pad = last[FRAME_WIDTH - 1];
    let pad_usize = pad as usize;
    if pad == 0 || pad_usize > FRAME_WIDTH {
        return Err(FubukiError::InvalidFramePadding);
    }

    let start = FRAME_WIDTH - pad_usize;
    let mut ok = 1u8;
    for (idx, &byte) in last.iter().enumerate() {
        let in_pad = (idx >= start) as u8;
        let eq = byte.ct_eq(&pad).unwrap_u8();
        ok &= (in_pad ^ 1) | eq;
    }

    if ok != 1 {
        return Err(FubukiError::InvalidFramePadding);
    }
    Ok(&last[..start])
}

pub use filter::winnow_stream;
pub use scatter::{scatter_stream, scatter_stream_with_window};
