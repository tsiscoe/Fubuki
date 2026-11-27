//! Mode A constant-time MAC verifier and out-of-order reassembler (`winnow`).

use std::collections::{BTreeMap, BTreeSet};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::{
    AONT_CANARY_FRAMES, FRAME_WIDTH, MAC_TAG_LEN, STREAM_SEED_LEN, TUPLE_WIRE_LEN,
    aont_package_decode, blind_sequence_index_with_subkey, compute_wheat_mac,
    derive_seq_blind_key,
};
use crate::{FubukiError, FubukiResult};

/// Authentic recovered frame paired with whether its MAC authenticated as the `EOS` domain.
#[derive(Zeroize)]
struct VerifiedFrame {
    symbol: [u8; FRAME_WIDTH],
    is_eos: bool,
}

/// Winnow an incoming cipherless stream back into authentic plaintext inside `Zeroizing<Vec<u8>>`.
///
/// Evaluates `subtle::ConstantTimeEq` across every tuple regardless of match outcome and surfaces
/// deterministic `MissingSequenceFrame(s_i)` errors on single-bit tamper or wrong keys.
pub fn winnow_stream(stream: &[u8], k_mac: &[u8; 32]) -> FubukiResult<Zeroizing<Vec<u8>>> {
    if stream.len() < STREAM_SEED_LEN + TUPLE_WIRE_LEN
        || !(stream.len() - STREAM_SEED_LEN).is_multiple_of(TUPLE_WIRE_LEN)
    {
        return Err(FubukiError::InvalidWireAlignment {
            len: stream.len(),
            tuple_size: TUPLE_WIRE_LEN,
        });
    }

    let mut ns = [0u8; STREAM_SEED_LEN];
    ns.copy_from_slice(&stream[..STREAM_SEED_LEN]);

    let body = &stream[STREAM_SEED_LEN..];
    let mut verified: BTreeMap<u64, VerifiedFrame> = BTreeMap::new();
    let mut seen_seqs: BTreeSet<u64> = BTreeSet::new();
    let mut eos_seq: Option<u64> = None;

    let mut k_seq = derive_seq_blind_key(k_mac);
    let (chunks, _) = body.as_chunks::<TUPLE_WIRE_LEN>();
    for (slot_idx, chunk) in chunks.iter().enumerate() {
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&chunk[0..8]);
        let blinded_seq = u64::from_le_bytes(seq_bytes);
        let seq_idx = blind_sequence_index_with_subkey(&k_seq, &ns, slot_idx as u64, blinded_seq);
        seen_seqs.insert(seq_idx);

        let mut symbol = [0u8; FRAME_WIDTH];
        symbol.copy_from_slice(&chunk[8..8 + FRAME_WIDTH]);

        let mut mac = [0u8; MAC_TAG_LEN];
        mac.copy_from_slice(&chunk[8 + FRAME_WIDTH..TUPLE_WIRE_LEN]);

        let expected_wheat = compute_wheat_mac(k_mac, &ns, seq_idx, &symbol, false);
        let expected_eos = compute_wheat_mac(k_mac, &ns, seq_idx, &symbol, true);

        let is_wheat = mac.ct_eq(&expected_wheat).unwrap_u8();
        let is_eos = mac.ct_eq(&expected_eos).unwrap_u8();

        if (is_wheat | is_eos) == 1 {
            let eos_flag = is_eos == 1;
            if let Some(existing) = verified.get(&seq_idx) {
                if existing.symbol.ct_eq(&symbol).unwrap_u8() != 1 || existing.is_eos != eos_flag {
                    symbol.zeroize();
                    k_seq.zeroize();
                    return Err(FubukiError::DuplicateSequenceFrame(seq_idx));
                }
            } else {
                verified.insert(
                    seq_idx,
                    VerifiedFrame {
                        symbol,
                        is_eos: eos_flag,
                    },
                );
            }
            if eos_flag {
                if let Some(prev_eos) = eos_seq
                    && prev_eos != seq_idx
                {
                    symbol.zeroize();
                    k_seq.zeroize();
                    return Err(FubukiError::DuplicateSequenceFrame(seq_idx));
                }
                eos_seq = Some(seq_idx);
            }
        }
        symbol.zeroize();
    }
    k_seq.zeroize();

    let Some(last_seq) = eos_seq else {
        // Under keyed sequence blinding (`FUBUKI-HORDE-05`), wrong `k_mac` yields pseudorandom
        // `seen_seqs` across `u64`; surface deterministic `MissingSequenceFrame(0)` when frame 0
        // was never authenticated, or the lowest missing contiguous frame `0..` before EOS.
        let mut missing = 0u64;
        while verified.contains_key(&missing) {
            missing += 1;
        }
        if seen_seqs.is_empty() {
            return Err(FubukiError::MissingEndOfStream);
        }
        return Err(FubukiError::MissingSequenceFrame(missing));
    };

    for expected_seq in 0..=last_seq {
        if !verified.contains_key(&expected_seq) {
            return Err(FubukiError::MissingSequenceFrame(expected_seq));
        }
    }

    if verified.len() as u64 != last_seq + 1 {
        let extra = verified
            .keys()
            .copied()
            .find(|&s| s > last_seq)
            .unwrap_or(last_seq + 1);
        return Err(FubukiError::DuplicateSequenceFrame(extra));
    }

    if (last_seq as usize + 1) <= AONT_CANARY_FRAMES {
        return Err(FubukiError::MissingEndOfStream);
    }

    let mut ordered_frames =
        Zeroizing::new(Vec::with_capacity(last_seq as usize + 1));
    for seq in 0..=last_seq {
        if let Some(mut frame) = verified.remove(&seq) {
            ordered_frames.push(frame.symbol);
            frame.zeroize();
        }
    }

    aont_package_decode(&ordered_frames)
}
