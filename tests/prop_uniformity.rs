use proptest::prelude::*;
use rand::rngs::OsRng;
use ratatui::{Terminal, backend::TestBackend};
use x25519_dalek::{PublicKey, StaticSecret};

use fubuki::FubukiError;
use fubuki::audit::audit_bytes;
use fubuki::kdf::KdfProfile;
use fubuki::pubkey::{
    compute_handshake_token, format_challenge_token, generate_keypair, parse_credential_input,
    parse_public_key_spec, parse_secret_key_spec,
};
use fubuki::tui::FubukiTuiApp;
use fubuki::tui::panes::{render, sanitize_for_tui};
use fubuki::volume::elligator::{
    elligator2_branch_sign, elligator2_decode, elligator2_generate_ephemeral,
};
use fubuki::volume::{
    BLOCK_SIZE, PREAMBLE_SIZE, init_and_seal_dual_pubkeys_bytes, init_volume_bytes,
    init_volume_dual_bytes, init_volume_dual_pubkeys_bytes, seal_volume_bytes,
    seal_volume_for_pubkey_bytes, unlock_volume_bytes, unlock_volume_with_modality_bytes,
};

#[test]
fn elligator2_10000_samples_msb_branch_and_chi_square_uniformity() {
    const SAMPLES: usize = 10_000;
    let mut rng = OsRng;
    let mut concat = Vec::with_capacity(SAMPLES * 32);
    let mut bit254_ones = 0usize;
    let mut bit255_ones = 0usize;
    let mut branch_pos = 0usize;

    for _ in 0..SAMPLES {
        let (sk, repr) = elligator2_generate_ephemeral(&mut rng);
        let pk = PublicKey::from(&sk);
        assert_eq!(
            elligator2_decode(&repr),
            *pk.as_bytes(),
            "decoded Elligator2 u-coordinate must match X25519 public key"
        );

        bit254_ones += usize::from((repr[31] >> 6) & 1);
        bit255_ones += usize::from((repr[31] >> 7) & 1);
        if elligator2_branch_sign(&repr) == 1 {
            branch_pos += 1;
        }
        concat.extend_from_slice(&repr);
    }

    let freq_254 = bit254_ones as f64 / SAMPLES as f64;
    let freq_255 = bit255_ones as f64 / SAMPLES as f64;
    let freq_branch = branch_pos as f64 / SAMPLES as f64;
    let three_sigma = 3.0 * (0.25f64 / SAMPLES as f64).sqrt(); // 0.015

    assert!(
        (freq_254 - 0.50).abs() <= three_sigma,
        "bit 254 frequency {freq_254:.4} outside 3-sigma [0.485, 0.515]"
    );
    assert!(
        (freq_255 - 0.50).abs() <= three_sigma,
        "bit 255 frequency {freq_255:.4} outside 3-sigma [0.485, 0.515]"
    );
    assert!(
        (freq_branch - 0.50).abs() <= three_sigma,
        "branch sign frequency {freq_branch:.4} outside 3-sigma [0.485, 0.515]"
    );

    let report = audit_bytes(&concat);
    assert!(
        report.chi_square_p_value > 0.001,
        "Elligator2 32B chi-square p-value too low: {}",
        report.chi_square_p_value
    );
    assert!(report.shannon_entropy_bits_per_byte > 7.99);
    assert!(report.detected_magic_signatures.is_empty());
    assert!(report.is_indistinguishable_noise);
}

#[test]
fn elligator2_hybrid_x25519_key_agreement_matches_ephemeral_secret() {
    let mut rng = OsRng;
    let recip_sk = StaticSecret::random_from_rng(rng);
    let recip_pk = PublicKey::from(&recip_sk);

    let (eph_sk, repr) = elligator2_generate_ephemeral(&mut rng);
    let decoded_u = elligator2_decode(&repr);
    let eph_pk = PublicKey::from(decoded_u);

    let sender_shared = eph_sk.diffie_hellman(&recip_pk);
    let receiver_shared = recip_sk.diffie_hellman(&eph_pk);
    assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn prop_dual_volume_coercion_symmetry_and_uniform_noise(
        decoy_payload in prop::collection::vec(any::<u8>(), 1..=8192),
        sov_payload in prop::collection::vec(any::<u8>(), 1..=16384),
        suffix in any::<u32>(),
    ) {
        let total_blocks = 128u64; // 512 KiB container
        let decoy_max = 32u64;     // 25% decoy ceiling
        let p_duress = format!("duress-pass-{suffix}");
        let p_sov = format!("sovereign-pass-{suffix}");
        let p_wrong = format!("wrong-pass-{suffix}");

        let (mut container, beta_duress, beta_sov) = init_volume_dual_bytes(
            total_blocks,
            Some(decoy_max),
            p_duress.as_bytes(),
            p_sov.as_bytes(),
            KdfProfile::fast(),
        ).expect("dual init must succeed");

        prop_assert_eq!(container.len(), PREAMBLE_SIZE + (total_blocks as usize) * BLOCK_SIZE);
        prop_assert!(beta_duress < decoy_max);
        prop_assert!(beta_sov >= decoy_max && beta_sov < total_blocks);

        // Wrong passphrase on empty container must yield generic AuthenticationFailed.
        prop_assert!(matches!(
            unlock_volume_bytes(&container, p_wrong.as_bytes(), KdfProfile::fast()),
            Err(FubukiError::AuthenticationFailed)
        ));

        let (a0, b0_cnt) = seal_volume_bytes(
            &mut container,
            p_duress.as_bytes(),
            &decoy_payload,
            true,
            KdfProfile::fast(),
        ).expect("decoy seal");
        prop_assert_eq!(a0, beta_duress);
        prop_assert!((a0 as usize + b0_cnt as usize) <= decoy_max as usize);

        // Wrong passphrase on 1-slot container must yield identical AuthenticationFailed.
        prop_assert!(matches!(
            unlock_volume_bytes(&container, p_wrong.as_bytes(), KdfProfile::fast()),
            Err(FubukiError::AuthenticationFailed)
        ));

        let (a1, _b1_cnt) = seal_volume_bytes(
            &mut container,
            p_sov.as_bytes(),
            &sov_payload,
            false,
            KdfProfile::fast(),
        ).expect("sovereign seal");
        prop_assert_eq!(a1, beta_sov);

        // Branchless single-path unlock recovers exact Slot 0 or Slot 1 payload.
        let unlocked_decoy = unlock_volume_bytes(&container, p_duress.as_bytes(), KdfProfile::fast())
            .expect("decoy unlock");
        prop_assert_eq!(unlocked_decoy.payload.as_slice(), decoy_payload.as_slice());
        prop_assert_eq!(unlocked_decoy.anchor_block, beta_duress);

        let unlocked_sov = unlock_volume_bytes(&container, p_sov.as_bytes(), KdfProfile::fast())
            .expect("sovereign unlock");
        prop_assert_eq!(unlocked_sov.payload.as_slice(), sov_payload.as_slice());
        prop_assert_eq!(unlocked_sov.anchor_block, beta_sov);

        // Wrong passphrase on 2-slot container remains indistinguishable.
        prop_assert!(matches!(
            unlock_volume_bytes(&container, p_wrong.as_bytes(), KdfProfile::fast()),
            Err(FubukiError::AuthenticationFailed)
        ));

        // Forensic entropy audit confirms zero cleartext slot signatures and uniform noise.
        let audit = audit_bytes(&container);
        prop_assert!(audit.detected_magic_signatures.is_empty());
        prop_assert!(audit.shannon_entropy_bits_per_byte > 7.98);
        prop_assert!(audit.is_indistinguishable_noise);
    }
}

#[test]
fn production_64mib_argon2id_and_decoy_ceiling_enforcement() {
    let total_blocks = 64u64;
    let p_duress = b"operator-duress-token";
    let p_sov = b"operator-sovereign-quorum";

    let (mut container, beta_d, beta_s) = init_volume_dual_bytes(
        total_blocks,
        Some(16),
        p_duress,
        p_sov,
        KdfProfile::production(),
    )
    .expect("production 64 MiB Argon2id dual provisioning");
    assert!(beta_d < 16);
    assert!(beta_s >= 16);

    let oversize_decoy = vec![0x55u8; 20 * BLOCK_SIZE];
    let err = seal_volume_bytes(
        &mut container,
        p_duress,
        &oversize_decoy,
        true,
        KdfProfile::production(),
    )
    .expect_err("decoy mode must enforce 25% block span ceiling");
    assert!(matches!(err, FubukiError::PayloadExceedsCapacity { .. }));

    let small_decoy = b"staging-expired-key=0000";
    seal_volume_bytes(
        &mut container,
        p_duress,
        small_decoy,
        true,
        KdfProfile::production(),
    )
    .expect("small decoy seal");

    let secret_shard = b"tontine-vss-shard-03-production-secret";
    seal_volume_bytes(
        &mut container,
        p_sov,
        secret_shard,
        false,
        KdfProfile::production(),
    )
    .expect("sovereign seal");

    let unlocked_s = unlock_volume_bytes(&container, p_sov, KdfProfile::production())
        .expect("unlock sovereign under 64 MiB profile");
    assert_eq!(unlocked_s.payload.as_slice(), secret_shard);

    // Also verify standalone unanchored container initialization + seal/unlock.
    let mut single = init_volume_bytes(32).expect("single init");
    seal_volume_bytes(
        &mut single,
        b"solo-key",
        b"solo-payload",
        false,
        KdfProfile::fast(),
    )
    .expect("solo seal");
    let unlocked_solo =
        unlock_volume_bytes(&single, b"solo-key", KdfProfile::fast()).expect("solo unlock");
    assert_eq!(unlocked_solo.payload.as_slice(), b"solo-payload");
}

#[test]
fn tui_3_pane_testbackend_and_zero_hidden_slot_leakage() {
    let total_blocks = 128u64;
    let decoy_max = 32u64;
    let p_duress = "duress-tui-test";
    let p_sov = "sovereign-tui-test";

    let (mut container, beta_d, beta_s) = init_volume_dual_bytes(
        total_blocks,
        Some(decoy_max),
        p_duress.as_bytes(),
        p_sov.as_bytes(),
        KdfProfile::fast(),
    )
    .expect("init");

    seal_volume_bytes(
        &mut container,
        p_duress.as_bytes(),
        b"benign operational decoy note",
        true,
        KdfProfile::fast(),
    )
    .expect("seal decoy");
    seal_volume_bytes(
        &mut container,
        p_sov.as_bytes(),
        b"crown-jewel-sovereign-payload",
        false,
        KdfProfile::fast(),
    )
    .expect("seal sovereign");

    // Inject malicious ANSI escape in target label to verify CWE-150 sanitization.
    let mut app = FubukiTuiApp::from_bytes("calib\x1b[31m_sensor_raw.dat", Some(container));
    app.kdf_profile = KdfProfile::fast();
    app.passphrase_buf.push_str(p_duress);
    app.attempt_unlock();

    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|f| render(f, &app)).expect("draw");

    let buf_str: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();

    assert!(buf_str.contains("[01] STREAM & STRIDE INSPECTOR"));
    assert!(buf_str.contains("[02] CRYPTOGRAPHIC GATE & PIPELINE"));
    assert!(buf_str.contains("[03] INDISTINGUISHABILITY TELEMETRY"));
    assert!(buf_str.contains(&format!("Blocks [{beta_d}..")));
    assert!(
        !buf_str.contains(p_duress),
        "plaintext passphrase must never render"
    );
    assert!(
        !buf_str.contains(&format!("[{beta_s}..")),
        "hidden slot anchor must never leak"
    );
    assert!(
        !buf_str.contains('\u{001b}'),
        "ANSI escape must be stripped"
    );
    assert_eq!(sanitize_for_tui("ok\x1b[2Jbad"), "ok[2Jbad");
}

#[test]
fn mahajani_pubkey_handshake_and_hybrid_dual_volume_coercion_symmetry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let auth_dir = dir.path().join("authorized_keys");
    std::fs::create_dir_all(&auth_dir).expect("mkdir authorized_keys");

    let kp_duress = generate_keypair();
    let kp_sov = generate_keypair();
    std::fs::write(auth_dir.join("alice_duress.asc"), &kp_duress.armored_asc)
        .expect("write duress .asc");
    std::fs::write(auth_dir.join("alice_sov.asc"), &kp_sov.armored_asc).expect("write sov .asc");

    // Verify Mahajani-style username lookup in authorized_keys/*.asc.
    let pk_duress =
        parse_public_key_spec("alice_duress", Some(&auth_dir)).expect("load duress .asc");
    let pk_sov = parse_public_key_spec("alice_sov", Some(&auth_dir)).expect("load sov .asc");
    assert_eq!(pk_duress.as_bytes(), kp_duress.public.as_bytes());
    assert_eq!(pk_sov.as_bytes(), kp_sov.public.as_bytes());

    let sov_pin = b"hybrid-pin-99";
    let dual = init_volume_dual_pubkeys_bytes(
        128,
        Some(32),
        &pk_duress,
        &pk_sov,
        None,
        Some(sov_pin),
        KdfProfile::fast(),
    )
    .expect("dual pubkey init");

    let mut container = dual.container.clone();
    let beta_d = dual.duress_anchor;
    let beta_s = dual.sov_anchor;
    assert!(beta_d < 32);
    assert!(beta_s >= 32);

    let eph_sk = StaticSecret::from(*dual.ephemeral_secret);
    let decoy_msg = b"decoy-authorized-keys-receipt";
    let sov_msg = b"sovereign-hybrid-hundi-shard-payload";

    // Seal Slot 0 with pure pubkey handshake (zero passphrase).
    seal_volume_for_pubkey_bytes(
        &mut container,
        &pk_duress,
        Some(&eph_sk),
        None,
        decoy_msg,
        true,
        KdfProfile::fast(),
    )
    .expect("seal pure pubkey decoy");

    // Seal Slot 1 with hybrid pubkey handshake + passphrase.
    seal_volume_for_pubkey_bytes(
        &mut container,
        &pk_sov,
        Some(&eph_sk),
        Some(sov_pin),
        sov_msg,
        false,
        KdfProfile::fast(),
    )
    .expect("seal hybrid pubkey sovereign");

    // Derive the volume challenge S_0[0..32] and compute both handshake responses off-host.
    let mut s0_repr = [0u8; 32];
    s0_repr.copy_from_slice(&container[0..32]);
    let chal = format_challenge_token(&s0_repr);
    assert!(chal.starts_with("fubuki-chal-v1:"));

    let sk_duress =
        parse_secret_key_spec(&kp_duress.secret_token).expect("parse duress secret token");
    let sk_sov = parse_secret_key_spec(&kp_sov.secret_token).expect("parse sov secret token");

    let hs_duress = compute_handshake_token(&sk_duress, &s0_repr);
    let hs_sov = compute_handshake_token(&sk_sov, &s0_repr);

    // 1. Pure Pubkey Handshake unlocks Slot 0 cleanly.
    let cred0 = parse_credential_input(&hs_duress).expect("parse pure handshake");
    assert!(cred0.passphrase.is_none());
    let unlocked0 = unlock_volume_with_modality_bytes(
        &container,
        cred0.passphrase.as_deref().map(Vec::as_slice),
        cred0.handshake.as_deref(),
        KdfProfile::fast(),
    )
    .expect("unlock pure pubkey Slot 0");
    assert_eq!(unlocked0.payload.as_slice(), decoy_msg);
    assert_eq!(unlocked0.anchor_block, beta_d);

    // 2. Submitting sovereign handshake WITHOUT its paired hybrid passphrase fails cleanly.
    let cred_missing = parse_credential_input(&hs_sov).expect("parse sov handshake");
    assert!(matches!(
        unlock_volume_with_modality_bytes(
            &container,
            cred_missing.passphrase.as_deref().map(Vec::as_slice),
            cred_missing.handshake.as_deref(),
            KdfProfile::fast(),
        ),
        Err(FubukiError::AuthenticationFailed)
    ));

    // 3. Combined Hybrid (`<pass>+fubuki-hs-v1:<hex>`) unlocks Slot 1 cleanly.
    let hybrid_cred = format!("hybrid-pin-99+{}", hs_sov.as_str());
    let cred1 = parse_credential_input(&hybrid_cred).expect("parse hybrid credential");
    let unlocked1 = unlock_volume_with_modality_bytes(
        &container,
        cred1.passphrase.as_deref().map(Vec::as_slice),
        cred1.handshake.as_deref(),
        KdfProfile::fast(),
    )
    .expect("unlock hybrid Slot 1");
    assert_eq!(unlocked1.payload.as_slice(), sov_msg);
    assert_eq!(unlocked1.anchor_block, beta_s);

    // 4. TUI unlocks via Hundi handshake response and exposes challenge without leaking secret or Slot 1.
    let mut app = FubukiTuiApp::from_bytes("hundi_volume.dat", Some(container));
    app.kdf_profile = KdfProfile::fast();
    app.passphrase_buf.push_str(&hs_duress);
    assert_eq!(app.challenge_token().as_deref(), Some(chal.as_str()));
    app.attempt_unlock();

    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|f| render(f, &app)).expect("draw");
    let buf_str: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(buf_str.contains(&format!("Blocks [{beta_d}..")));
    assert!(buf_str.contains("fubuki-chal-v1:"));
    assert!(!buf_str.contains(hs_duress.as_str()));
    assert!(!buf_str.contains(&format!("[{beta_s}..")));

    // 5. Compound zero-exposure init_and_seal_dual_pubkeys_bytes keeps ephemeral key strictly in RAM.
    let one_shot = init_and_seal_dual_pubkeys_bytes(
        64,
        Some(16),
        &pk_duress,
        &pk_sov,
        None,
        Some(sov_pin),
        b"one-shot-decoy",
        b"one-shot-sovereign",
        KdfProfile::fast(),
    )
    .expect("one-shot dual pubkey seal");
    assert!(one_shot.duress_anchor < 16);
    assert!(one_shot.sov_anchor >= 16);

    let mut oneshot_repr = [0u8; 32];
    oneshot_repr.copy_from_slice(&one_shot.container[0..32]);
    let oneshot_hs_d = compute_handshake_token(&sk_duress, &oneshot_repr);
    let oneshot_hs_s = compute_handshake_token(&sk_sov, &oneshot_repr);

    let cd = parse_credential_input(&oneshot_hs_d).expect("parse one-shot duress hs");
    let ud = unlock_volume_with_modality_bytes(
        &one_shot.container,
        cd.passphrase.as_deref().map(Vec::as_slice),
        cd.handshake.as_deref(),
        KdfProfile::fast(),
    )
    .expect("unlock one-shot decoy");
    assert_eq!(ud.payload.as_slice(), b"one-shot-decoy");

    let cs = parse_credential_input(&format!("hybrid-pin-99+{}", oneshot_hs_s.as_str()))
        .expect("parse one-shot sov hybrid");
    let us = unlock_volume_with_modality_bytes(
        &one_shot.container,
        cs.passphrase.as_deref().map(Vec::as_slice),
        cs.handshake.as_deref(),
        KdfProfile::fast(),
    )
    .expect("unlock one-shot sovereign");
    assert_eq!(us.payload.as_slice(), b"one-shot-sovereign");
}
