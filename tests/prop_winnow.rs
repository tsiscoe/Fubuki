use proptest::prelude::*;

use fubuki::FubukiError;
use fubuki::audit::audit_bytes;
use fubuki::winnow::{
    FRAME_WIDTH, MAC_TAG_LEN, STREAM_SEED_LEN, TUPLE_WIRE_LEN, blind_sequence_index,
    compute_wheat_mac, scatter_stream, scatter_stream_with_window, winnow_stream,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_winnowing_lossless_across_ratios_and_window_reorderings(
        payload in prop::collection::vec(any::<u8>(), 0..=65536),
        key in any::<[u8; 32]>(),
        ratio in 1u8..=31,
        window in 0usize..=64,
    ) {
        let scattered = scatter_stream_with_window(&payload, &key, ratio, window)
            .expect("scatter should succeed for valid ratio");

        prop_assert_eq!(
            (scattered.len() - STREAM_SEED_LEN) % TUPLE_WIRE_LEN,
            0,
            "wire length must remain an exact multiple of 40B tuples after 16B seed"
        );

        let recovered = winnow_stream(&scattered, &key)
            .expect("winnow must losslessly reconstruct scattered payload");
        prop_assert_eq!(recovered.as_slice(), payload.as_slice());
    }

    #[test]
    fn prop_single_bit_tamper_in_wheat_frame_triggers_missing_sequence_frame(
        payload in prop::collection::vec(any::<u8>(), 0..=4096),
        key in any::<[u8; 32]>(),
        ratio in 1u8..=11,
        target_frame_seed in any::<usize>(),
        bit_offset in 0usize..(8 * (FRAME_WIDTH + MAC_TAG_LEN)),
    ) {
        let mut scattered = scatter_stream(&payload, &key, ratio)
            .expect("scatter should succeed");

        let mut ns = [0u8; STREAM_SEED_LEN];
        ns.copy_from_slice(&scattered[..STREAM_SEED_LEN]);

        // Locate all authentic wheat tuples in the scattered stream.
        let mut wheat_positions: Vec<(usize, u64)> = Vec::new();
        let body = &scattered[STREAM_SEED_LEN..];
        let (chunks, _) = body.as_chunks::<TUPLE_WIRE_LEN>();
        for (slot_idx, chunk) in chunks.iter().enumerate() {
            let mut seq_raw = [0u8; 8];
            seq_raw.copy_from_slice(&chunk[0..8]);
            let seq_idx = blind_sequence_index(&key, &ns, slot_idx as u64, u64::from_le_bytes(seq_raw));
            let mut sym = [0u8; FRAME_WIDTH];
            sym.copy_from_slice(&chunk[8..8 + FRAME_WIDTH]);
            let mut mac = [0u8; MAC_TAG_LEN];
            mac.copy_from_slice(&chunk[8 + FRAME_WIDTH..TUPLE_WIRE_LEN]);

            let exp_w = compute_wheat_mac(&key, &ns, seq_idx, &sym, false);
            let exp_e = compute_wheat_mac(&key, &ns, seq_idx, &sym, true);
            if mac == exp_w || mac == exp_e {
                wheat_positions.push((slot_idx, seq_idx));
            }
        }

        prop_assert!(!wheat_positions.is_empty());
        let (victim_slot, expected_seq) = wheat_positions[target_frame_seed % wheat_positions.len()];
        let byte_idx = STREAM_SEED_LEN + victim_slot * TUPLE_WIRE_LEN + 8 + (bit_offset / 8);
        let bit_mask = 1u8 << (bit_offset % 8);
        scattered[byte_idx] ^= bit_mask;

        let err = winnow_stream(&scattered, &key)
            .expect_err("single-bit tamper inside authentic wheat symbol or MAC must fail");
        match err {
            FubukiError::MissingSequenceFrame(seq) => prop_assert_eq!(seq, expected_seq),
            other => prop_assert!(false, "expected MissingSequenceFrame({expected_seq}), got {other:?}"),
        }
    }
}

#[test]
fn mode_a_rejects_wrong_key_and_unaligned_streams_and_passes_entropy_audit() {
    let key_a = [0x11u8; 32];
    let key_b = [0x22u8; 32];
    let secret = b"TOP_SECRET_ENV_KEY=test-value\n".repeat(40);

    let stream = scatter_stream(&secret, &key_a, 7).expect("scatter");
    assert_eq!(
        winnow_stream(&stream, &key_a).expect("winnow").as_slice(),
        secret
    );

    let wrong = winnow_stream(&stream, &key_b).expect_err("wrong key must reject");
    assert!(matches!(wrong, FubukiError::MissingSequenceFrame(0)));

    let unaligned = &stream[..stream.len() - 1];
    assert!(matches!(
        winnow_stream(unaligned, &key_a),
        Err(FubukiError::InvalidWireAlignment { .. })
    ));

    let audit = audit_bytes(&stream);
    assert!(audit.detected_magic_signatures.is_empty());
    assert!(audit.shannon_entropy_bits_per_byte > 7.98);
    assert!(
        audit.is_indistinguishable_noise,
        "Mode A AONT-wrapped ASCII stream must pass chi-square uniformity audit: {audit:?}"
    );
    assert!(
        !String::from_utf8_lossy(&stream).contains("TOP_SECRET"),
        "Mode A scattered stream must never expose cleartext ASCII substrings"
    );

    // High-entropy payloads (e.g., Meade exports / random keys) scattered with Mode A framing
    // must pass full Pearson chi-square uniformity with zero statistical framing bias.
    let mut high_entropy_payload = vec![0u8; 2048];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut high_entropy_payload);
    let uniform_stream = scatter_stream(&high_entropy_payload, &key_a, 7).expect("scatter");
    let uniform_audit = audit_bytes(&uniform_stream);
    assert!(uniform_audit.detected_magic_signatures.is_empty());
    assert!(
        uniform_audit.is_indistinguishable_noise,
        "Mode A framing failed statistical uniformity audit: {uniform_audit:?}"
    );
    assert!(uniform_audit.shannon_entropy_bits_per_byte > 7.98);

    // Mode A also derives deterministic MAC keys from Mahajani-style Hundi handshake tokens.
    let hs_token = format!("fubuki-hs-v1:{}", hex::encode([0x42u8; 32]));
    let k_hs = fubuki::kdf::parse_or_derive_mac_key(&hs_token).expect("handshake MAC key");
    let k_hybrid = fubuki::kdf::parse_or_derive_mac_key(&format!("pin+{hs_token}"))
        .expect("hybrid handshake MAC key");
    assert_ne!(&*k_hs, &*k_hybrid);

    let msg = b"MAHAJANI_HANDSHAKE_STREAM_SECRET";
    let hs_stream = scatter_stream(msg, &k_hs, 5).expect("scatter with handshake MAC");
    assert_eq!(
        winnow_stream(&hs_stream, &k_hs)
            .expect("winnow with handshake MAC")
            .as_slice(),
        msg
    );
}
