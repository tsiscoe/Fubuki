//! Mode A constant-time MAC verifier and out-of-order reassembler (`winnow`).

use std::collections::{BTreeMap, BTreeSet};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::{
    FRAME_WIDTH, MAC_TAG_LEN, STREAM_SEED_LEN, TUPLE_WIRE_LEN, blind_sequence_index,
    compute_wheat_mac, pkcs7_strip_last_frame,
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

    let (chunks, _) = body.as_chunks::<TUPLE_WIRE_LEN>();
    for (slot_idx, chunk) in chunks.iter().enumerate() {
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&chunk[0..8]);
        let blinded_seq = u64::from_le_bytes(seq_bytes);
        let seq_idx = blind_sequence_index(&ns, slot_idx as u64, blinded_seq);
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
                    return Err(FubukiError::DuplicateSequenceFrame(seq_idx));
                }
                eos_seq = Some(seq_idx);
            }
        }
        symbol.zeroize();
    }

    let Some(last_seq) = eos_seq else {
        // Identify the lowest sequence index that appeared in the stream with zero valid MACs
        // (covers both wrong MAC keys and single-bit tampering of the final EOS frame).
        for &candidate_seq in &seen_seqs {
            if !verified.contains_key(&candidate_seq) {
                return Err(FubukiError::MissingSequenceFrame(candidate_seq));
            }
        }
        return Err(FubukiError::MissingEndOfStream);
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

    let mut out = Zeroizing::new(Vec::with_capacity((last_seq as usize + 1) * FRAME_WIDTH));
    for seq in 0..=last_seq {
        if let Some(mut frame) = verified.remove(&seq) {
            if seq == last_seq {
                let tail = pkcs7_strip_last_frame(&frame.symbol)?;
                out.extend_from_slice(tail);
            } else {
                out.extend_from_slice(&frame.symbol);
            }
            frame.zeroize();
        }
    }

    Ok(out)
}
