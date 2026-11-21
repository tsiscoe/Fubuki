//! Mode A packetization (`scatter`): emits interleaved wheat + CSPRNG chaff tuples.

use rand::RngCore;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use zeroize::Zeroize;

use super::{
    FRAME_WIDTH, MAC_TAG_LEN, STREAM_SEED_LEN, TUPLE_WIRE_LEN, blind_sequence_index,
    compute_wheat_mac, pkcs7_chunk_frames,
};
use crate::{FubukiError, FubukiResult};

/// Unblinded intermediate packet candidate before wire-slot sequence blinding.
#[derive(Clone, Zeroize)]
struct PacketTuple {
    seq_idx: u64,
    symbol: [u8; FRAME_WIDTH],
    mac: [u8; MAC_TAG_LEN],
}

/// Scatter `payload` into a headerless cipherless winnowing stream with `ratio` chaff tuples per
/// authentic wheat frame (default `ratio = 7`, producing `8` tuples per sequence index).
///
/// Uses zero encryption primitives: authentic frames carry keyed BLAKE3 tags while chaff frames
/// carry CSPRNG random symbols (`!= wheat`) and CSPRNG random tags.
pub fn scatter_stream(payload: &[u8], k_mac: &[u8; 32], ratio: u8) -> FubukiResult<Vec<u8>> {
    scatter_stream_with_window(payload, k_mac, ratio, 0)
}

/// Scatter `payload` with an optional inter-index sliding-window permutation (`window_tuples > 0`)
/// so wheat frames arrive out of sequence order on the wire while maintaining exact `N_s + slot_idx`
/// sequence blinding.
pub fn scatter_stream_with_window(
    payload: &[u8],
    k_mac: &[u8; 32],
    ratio: u8,
    window_tuples: usize,
) -> FubukiResult<Vec<u8>> {
    if ratio == 0 {
        return Err(FubukiError::InvalidRatio(ratio));
    }

    let mut rng = OsRng;
    let mut ns = [0u8; STREAM_SEED_LEN];
    rng.fill_bytes(&mut ns);

    let mut frames = pkcs7_chunk_frames(payload);
    let total_frames = frames.len();
    let tuples_per_frame = 1usize + usize::from(ratio);
    let total_tuples = total_frames
        .checked_mul(tuples_per_frame)
        .ok_or_else(|| FubukiError::ContainerGeometryError("stream tuple count overflow".into()))?;

    let mut candidates = Vec::with_capacity(total_tuples);

    for (idx, frame) in frames.iter().enumerate() {
        let seq_idx = idx as u64;
        let is_eos = idx + 1 == total_frames;
        let mac = compute_wheat_mac(k_mac, &ns, seq_idx, frame, is_eos);

        let mut group = Vec::with_capacity(tuples_per_frame);
        group.push(PacketTuple {
            seq_idx,
            symbol: *frame,
            mac,
        });

        for _ in 0..ratio {
            let mut fake_symbol = [0u8; FRAME_WIDTH];
            loop {
                rng.fill_bytes(&mut fake_symbol);
                if &fake_symbol != frame {
                    break;
                }
            }
            let mut fake_mac = [0u8; MAC_TAG_LEN];
            rng.fill_bytes(&mut fake_mac);
            group.push(PacketTuple {
                seq_idx,
                symbol: fake_symbol,
                mac: fake_mac,
            });
        }

        group.shuffle(&mut rng);
        candidates.extend(group);
    }

    for frame in &mut frames {
        frame.zeroize();
    }

    if window_tuples > 1 && candidates.len() > 1 {
        let step = window_tuples.min(candidates.len());
        for chunk in candidates.chunks_mut(step) {
            chunk.shuffle(&mut rng);
        }
        // Perform a second staggered window pass so frames straddle initial chunk boundaries too.
        let half = step / 2;
        if half > 0 && candidates.len() > half {
            for chunk in candidates[half..].chunks_mut(step) {
                chunk.shuffle(&mut rng);
            }
        }
    }

    let mut out = Vec::with_capacity(STREAM_SEED_LEN + total_tuples * TUPLE_WIRE_LEN);
    out.extend_from_slice(&ns);

    for (slot_idx, mut tuple) in candidates.into_iter().enumerate() {
        let blinded = blind_sequence_index(&ns, slot_idx as u64, tuple.seq_idx);
        out.extend_from_slice(&blinded.to_le_bytes());
        out.extend_from_slice(&tuple.symbol);
        out.extend_from_slice(&tuple.mac);
        tuple.zeroize();
    }

    Ok(out)
}
