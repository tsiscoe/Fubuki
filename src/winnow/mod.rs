//! Mode A: Cipherless Keyed-BLAKE3 Chaffing & Winnowing (`scatter` & `filter`).
//!
//! Wire format (zero magic bytes):
//! - Bytes `0..16`: Uniform 128-bit stream session seed `N_s`.
//! - Remaining bytes: integer multiple of 40-byte tuples `(LE64(blinded_seq) || symbol[16] || mac[16])`.

pub mod filter;
pub mod scatter;

use crate::{FubukiError, FubukiResult};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

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

/// Domain separation context for deriving the sequence-index blinding subkey from `k_mac`.
pub const DOMAIN_SEQ_BLIND: &[u8] = b"fubuki.wheat.seq_blind.v1";

/// Domain separation context for the keyless All-Or-Nothing Package Transform (AONT) XOF mask.
const DOMAIN_AONT_MASK: &str = "fubuki.aont.mask.v1";

/// Domain separation context for the keyless All-Or-Nothing Package Transform (AONT) canary digest.
const DOMAIN_AONT_BIND: &str = "fubuki.aont.bind.v1";

/// Number of 16-byte canary frames appended by the keyless BLAKE3 AONT (`32` bytes = `2` frames).
pub const AONT_CANARY_FRAMES: usize = 2;

/// Derive the 32-byte sequence-blinding subkey from `k_mac` so passive keyless observers cannot
/// unblind `seq_idx` or infer chaff ratio / payload frame counts (`FUBUKI-HORDE-05`).
pub fn derive_seq_blind_key(k_mac: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(k_mac, DOMAIN_SEQ_BLIND).as_bytes()
}

/// Self-inverse keyed blinding of monotonic sequence index `seq_idx` at physical wire slot
/// `slot_idx`: `seq_idx ^ Trunc64(BLAKE3_{k_seq}(N_s || LE64(slot_idx)))`.
pub fn blind_sequence_index(
    k_mac: &[u8; 32],
    ns: &[u8; STREAM_SEED_LEN],
    slot_idx: u64,
    seq_idx: u64,
) -> u64 {
    let mut k_seq = derive_seq_blind_key(k_mac);
    let out = blind_sequence_index_with_subkey(&k_seq, ns, slot_idx, seq_idx);
    k_seq.zeroize();
    out
}

pub(crate) fn blind_sequence_index_with_subkey(
    k_seq: &[u8; 32],
    ns: &[u8; STREAM_SEED_LEN],
    slot_idx: u64,
    seq_idx: u64,
) -> u64 {
    let mut hasher = blake3::Hasher::new_keyed(k_seq);
    hasher.update(ns);
    hasher.update(&slot_idx.to_le_bytes());
    let digest = hasher.finalize();
    let mut mask = [0u8; 8];
    mask.copy_from_slice(&digest.as_bytes()[0..8]);
    seq_idx ^ u64::from_le_bytes(mask)
}

/// Keyless BLAKE3 Sponge-AONT (All-Or-Nothing Package Transform) over PKCS#7-padded payload frames.
///
/// Preserves Rivest's "zero encryption keys" property while ensuring every individual 16-byte wheat
/// frame is marginally uniform over `{0,1}^128` (`FUBUKI-HORDE-01` — zero cleartext ASCII or
/// `[0x10; 16]` PKCS#7 padding blocks on the wire) and unreadable unless *every* authentic wheat
/// frame is winnowed via `k_mac`.
pub fn aont_package_encode(payload: &[u8]) -> Zeroizing<Vec<[u8; FRAME_WIDTH]>> {
    let mut raw_frames = pkcs7_chunk_frames(payload);
    let payload_bytes_len = raw_frames.len() * FRAME_WIDTH;

    let mut r_pkg = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *r_pkg);

    let mut masked_bytes = Zeroizing::new(vec![0u8; payload_bytes_len]);
    let mut xof = blake3::Hasher::new_derive_key(DOMAIN_AONT_MASK)
        .update(&*r_pkg)
        .finalize_xof();
    xof.fill(&mut masked_bytes);

    for (chunk_idx, frame) in raw_frames.iter_mut().enumerate() {
        let base = chunk_idx * FRAME_WIDTH;
        for b in 0..FRAME_WIDTH {
            masked_bytes[base + b] ^= frame[b];
        }
        frame.zeroize();
    }

    let bind_digest = blake3::Hasher::new_derive_key(DOMAIN_AONT_BIND)
        .update(&masked_bytes)
        .finalize();
    let mut canary = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        canary[i] = r_pkg[i] ^ bind_digest.as_bytes()[i];
    }

    let mut out = Zeroizing::new(Vec::with_capacity(raw_frames.len() + AONT_CANARY_FRAMES));
    let (chunks, _) = masked_bytes.as_chunks::<FRAME_WIDTH>();
    for &c in chunks {
        out.push(c);
    }
    let mut c0 = [0u8; FRAME_WIDTH];
    let mut c1 = [0u8; FRAME_WIDTH];
    c0.copy_from_slice(&canary[0..FRAME_WIDTH]);
    c1.copy_from_slice(&canary[FRAME_WIDTH..32]);
    out.push(c0);
    out.push(c1);
    c0.zeroize();
    c1.zeroize();
    out
}

/// Keyless inverse of `aont_package_encode`: recovers `r_pkg` from the 32-byte canary + full
/// masked package digest, unmasks the PKCS#7 frames, and strips constant-time padding.
pub fn aont_package_decode(frames: &[[u8; FRAME_WIDTH]]) -> FubukiResult<Zeroizing<Vec<u8>>> {
    if frames.len() <= AONT_CANARY_FRAMES {
        return Err(FubukiError::MissingEndOfStream);
    }
    let masked_frame_count = frames.len() - AONT_CANARY_FRAMES;
    let masked_len = masked_frame_count * FRAME_WIDTH;

    let mut masked_bytes = Zeroizing::new(Vec::with_capacity(masked_len));
    for frame in &frames[..masked_frame_count] {
        masked_bytes.extend_from_slice(frame);
    }

    let mut canary = Zeroizing::new([0u8; 32]);
    canary[0..FRAME_WIDTH].copy_from_slice(&frames[masked_frame_count]);
    canary[FRAME_WIDTH..32].copy_from_slice(&frames[masked_frame_count + 1]);

    let bind_digest = blake3::Hasher::new_derive_key(DOMAIN_AONT_BIND)
        .update(&masked_bytes)
        .finalize();
    let mut r_pkg = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        r_pkg[i] = canary[i] ^ bind_digest.as_bytes()[i];
    }

    let mut pad_stream = Zeroizing::new(vec![0u8; masked_len]);
    let mut xof = blake3::Hasher::new_derive_key(DOMAIN_AONT_MASK)
        .update(&*r_pkg)
        .finalize_xof();
    xof.fill(&mut pad_stream);

    for i in 0..masked_len {
        pad_stream[i] ^= masked_bytes[i];
    }

    let mut last_frame = Zeroizing::new([0u8; FRAME_WIDTH]);
    last_frame.copy_from_slice(&pad_stream[masked_len - FRAME_WIDTH..masked_len]);
    let stripped_tail = pkcs7_strip_last_frame(&last_frame)?;

    let prefix_len = masked_len - FRAME_WIDTH;
    let mut out = Zeroizing::new(Vec::with_capacity(prefix_len + stripped_tail.len()));
    out.extend_from_slice(&pad_stream[..prefix_len]);
    out.extend_from_slice(stripped_tail);
    Ok(out)
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
