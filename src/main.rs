#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use zeroize::{Zeroize, Zeroizing};

use fubuki::audit::audit_bytes;
use fubuki::cli::{Cli, Commands};
use fubuki::kdf::{KdfProfile, derive_mode_a_mac_key_from_handshake, parse_or_derive_mac_key};
use fubuki::pubkey::{
    compute_handshake_token, compute_sender_handshake, format_challenge_token, generate_keypair,
    parse_challenge_token, parse_credential_input, parse_public_key_spec, parse_secret_key_spec,
};
use fubuki::tui::{FubukiTuiApp, run_interactive_tui};
use fubuki::volume::elligator::elligator2_generate_ephemeral;
use fubuki::volume::{
    blocks_for_payload_region, init_and_seal_dual_pubkeys_bytes, init_volume_bytes,
    init_volume_dual_bytes, init_volume_dual_pubkeys_bytes, parse_size_spec,
    seal_volume_for_pubkey_bytes, seal_volume_with_modality_bytes,
    unlock_volume_with_modality_bytes, validate_container_len,
};
use fubuki::winnow::{scatter_stream, winnow_stream};

fn read_input_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    if path.as_os_str() == "-" {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read input from stdin")?;
        Ok(buf)
    } else {
        let data = std::fs::read(path)
            .with_context(|| format!("failed to read input file {}", path.display()))?;
        Ok(Zeroizing::new(data))
    }
}

fn write_output_bytes(path: &Path, data: &[u8]) -> Result<()> {
    if path.as_os_str() == "-" {
        let mut out = std::io::stdout().lock();
        out.write_all(data).context("failed to write stdout")?;
        out.flush()?;
    } else {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)
            .with_context(|| format!("failed to write output file {}", path.display()))?;
    }
    Ok(())
}

fn resolve_mac_key(key_env: &str, key_hex: Option<&str>) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(hex_str) = key_hex {
        return Ok(parse_or_derive_mac_key(hex_str)?);
    }
    if let Ok(raw) = std::env::var(key_env)
        && !raw.trim().is_empty()
    {
        let val = Zeroizing::new(raw);
        return Ok(parse_or_derive_mac_key(&val)?);
    }

    // Out-of-band TTY prompt (CONIN$ / /dev/tty) keeps stdin/stdout data pipes unpolluted
    // without forcing the operator to export keys into shell history.
    let entered = rpassword::prompt_password(
        "Mode A credential (passphrase, 64-hex, fubuki-hs-v1:<hex>, or pass+fubuki-hs-v1:<hex>): ",
    )
    .context("failed to read Mode A credential from controlling TTY")?;
    let z = Zeroizing::new(entered);
    Ok(parse_or_derive_mac_key(&z)?)
}

fn resolve_credential_raw(env_var: Option<&str>, prompt: &str) -> Result<Zeroizing<String>> {
    if let Some(var) = env_var {
        let val = std::env::var(var)
            .with_context(|| format!("credential environment variable {var} is not set"))?;
        if val.is_empty() {
            return Err(anyhow!("credential in {var} cannot be empty"));
        }
        return Ok(Zeroizing::new(val));
    }

    let entered = rpassword::prompt_password(prompt).context("failed to read credential")?;
    let z = Zeroizing::new(entered);
    if z.is_empty() {
        return Err(anyhow!("credential cannot be empty"));
    }
    Ok(z)
}

fn read_volume_challenge(path: &Path) -> Result<[u8; 32]> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read container {}", path.display()))?;
    let _ = validate_container_len(data.len())?;
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&data[0..32]);
    Ok(repr)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen {
            user,
            out_dir,
            json,
        } => {
            if user.is_empty()
                || user.len() > 64
                || !user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(anyhow!(
                    "username must be 1..=64 ASCII alphanumeric, '_', or '-' characters"
                ));
            }
            let kp = generate_keypair();
            std::fs::create_dir_all(&out_dir)?;
            let asc_path = out_dir.join(format!("{user}.asc"));
            std::fs::write(&asc_path, &kp.armored_asc)
                .with_context(|| format!("failed to write {}", asc_path.display()))?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "user": user,
                        "asc_path": asc_path,
                        "public_key": kp.public_token,
                        "secret_key": kp.secret_token.as_str(),
                    }))?
                );
            } else {
                println!("Wrote OpenPGP public key: {}", asc_path.display());
                println!("Public Token: {}", kp.public_token);
                println!("Private Key (keep off host): {}", kp.secret_token.as_str());
            }
        }

        Commands::Challenge { target, json } => {
            let repr = read_volume_challenge(&target)?;
            let chal = format_challenge_token(&repr);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "target": target,
                        "challenge": chal,
                    }))?
                );
            } else {
                println!("{chal}");
            }
        }

        Commands::Handshake {
            challenge,
            secret_env,
            pass_env,
            hybrid_pass,
        } => {
            let chal_path = Path::new(&challenge);
            let repr = if chal_path.is_file() {
                read_volume_challenge(chal_path)?
            } else {
                parse_challenge_token(&challenge)?
            };

            let sec_raw =
                resolve_credential_raw(secret_env.as_deref(), "Private Key (fubuki-sec-v1:...): ")?;
            let sk = parse_secret_key_spec(&sec_raw)?;
            let hs_token = compute_handshake_token(&sk, &repr)?;

            let hybrid_pw = if let Some(var) = pass_env.as_deref() {
                Some(resolve_credential_raw(Some(var), "")?)
            } else if hybrid_pass {
                Some(resolve_credential_raw(None, "Hybrid passphrase: ")?)
            } else {
                None
            };

            if let Some(pw) = hybrid_pw {
                let mut combined = Zeroizing::new(format!("{}+{}", pw.as_str(), hs_token.as_str()));
                println!("{}", combined.as_str());
                combined.zeroize();
            } else {
                println!("{}", hs_token.as_str());
            }
        }

        Commands::Scatter {
            ratio,
            key_env,
            key_hex,
            pubkey,
            authorized_keys,
            in_path,
            out_path,
        } => {
            let k_mac = if let Some(pk_spec) = pubkey {
                let recip_pub = parse_public_key_spec(&pk_spec, Some(&authorized_keys))?;
                let (sk_eph, repr) = elligator2_generate_ephemeral(&mut rand::rngs::OsRng);
                let hs = compute_sender_handshake(&sk_eph, &recip_pub)?;
                let chal = format_challenge_token(&repr);
                eprintln!("Out-of-Band Mode A Hundi Challenge: {chal}");
                derive_mode_a_mac_key_from_handshake(None, &hs)
            } else {
                resolve_mac_key(&key_env, key_hex.as_deref())?
            };
            let payload = read_input_bytes(&in_path)?;
            let stream = scatter_stream(&payload, &k_mac, ratio)?;
            write_output_bytes(&out_path, &stream)?;
        }

        Commands::Winnow {
            key_env,
            key_hex,
            in_path,
            out_path,
        } => {
            let k_mac = resolve_mac_key(&key_env, key_hex.as_deref())?;
            let stream = read_input_bytes(&in_path)?;
            let recovered = winnow_stream(&stream, &k_mac)?;
            write_output_bytes(&out_path, &recovered)?;
        }

        Commands::InitVolume {
            size,
            out,
            decoy_max,
            duress_pass_env,
            sov_pass_env,
            duress_pubkey,
            sov_pubkey,
            duress_in,
            sov_in,
            authorized_keys,
            json,
            kdf_profile,
        } => {
            let bytes = parse_size_spec(&size)?;
            let total_blocks = blocks_for_payload_region(bytes)?;
            let decoy_blocks = match decoy_max {
                Some(spec) => Some(blocks_for_payload_region(parse_size_spec(&spec)?)?),
                None => None,
            };
            let profile: KdfProfile = kdf_profile.into();

            let (container, maybe_eph_sec): (Vec<u8>, Option<Zeroizing<[u8; 32]>>) = match (
                duress_pubkey.as_deref(),
                sov_pubkey.as_deref(),
            ) {
                (Some(dp_spec), Some(sp_spec)) => {
                    let dp = parse_public_key_spec(dp_spec, Some(&authorized_keys))?;
                    let sp = parse_public_key_spec(sp_spec, Some(&authorized_keys))?;
                    let d_pw = match duress_pass_env.as_deref() {
                        Some(v) => Some(resolve_credential_raw(Some(v), "")?),
                        None => None,
                    };
                    let s_pw = match sov_pass_env.as_deref() {
                        Some(v) => Some(resolve_credential_raw(Some(v), "")?),
                        None => None,
                    };

                    match (duress_in.as_deref(), sov_in.as_deref()) {
                        (Some(d_path), Some(s_path)) => {
                            let d_payload = read_input_bytes(d_path)?;
                            let s_payload = read_input_bytes(s_path)?;
                            let sealed = init_and_seal_dual_pubkeys_bytes(
                                total_blocks,
                                decoy_blocks,
                                &dp,
                                &sp,
                                d_pw.as_deref().map(|s| s.as_bytes()),
                                s_pw.as_deref().map(|s| s.as_bytes()),
                                &d_payload,
                                &s_payload,
                                profile,
                            )?;
                            (sealed.container.clone(), None)
                        }
                        (None, None) => {
                            let dual = init_volume_dual_pubkeys_bytes(
                                total_blocks,
                                decoy_blocks,
                                &dp,
                                &sp,
                                d_pw.as_deref().map(|s| s.as_bytes()),
                                s_pw.as_deref().map(|s| s.as_bytes()),
                                profile,
                            )?;
                            (dual.container.clone(), Some(dual.ephemeral_secret.clone()))
                        }
                        _ => {
                            return Err(anyhow!(
                                "provide both --duress-in and --sov-in for one-shot compound sealing, or omit both"
                            ));
                        }
                    }
                }
                (None, None) => match (duress_pass_env.as_deref(), sov_pass_env.as_deref()) {
                    (Some(d_var), Some(s_var)) => {
                        let d_pw = resolve_credential_raw(Some(d_var), "Duress passphrase: ")?;
                        let s_pw = resolve_credential_raw(Some(s_var), "Sovereign passphrase: ")?;
                        let (buf, _, _) = init_volume_dual_bytes(
                            total_blocks,
                            decoy_blocks,
                            d_pw.as_bytes(),
                            s_pw.as_bytes(),
                            profile,
                        )?;
                        (buf, None)
                    }
                    (None, None) => {
                        if decoy_blocks.is_some() {
                            return Err(anyhow!(
                                "--decoy-max requires dual-slot credentials (--duress-pass-env + --sov-pass-env or --duress-pubkey + --sov-pubkey) to rejection-sample S_0"
                            ));
                        }
                        if duress_in.is_some() || sov_in.is_some() {
                            return Err(anyhow!(
                                "--duress-in / --sov-in require --duress-pubkey and --sov-pubkey"
                            ));
                        }
                        (init_volume_bytes(total_blocks)?, None)
                    }
                    _ => {
                        return Err(anyhow!(
                            "provide both --duress-pass-env and --sov-pass-env, or omit both"
                        ));
                    }
                },
                _ => {
                    return Err(anyhow!(
                        "provide both --duress-pubkey and --sov-pubkey for dual-pubkey separation"
                    ));
                }
            };

            let mut repr = [0u8; 32];
            repr.copy_from_slice(&container[0..32]);
            let chal = format_challenge_token(&repr);
            write_output_bytes(&out, &container)?;

            if json {
                let eph_token = maybe_eph_sec
                    .as_ref()
                    .map(|b| Zeroizing::new(format!("fubuki-sec-v1:{}", hex::encode(**b))));
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "volume": out,
                        "bytes": container.len(),
                        "blocks": total_blocks,
                        "challenge": chal,
                        "ephemeral_sealing_key": eph_token.as_deref().map(String::as_str),
                    }))?
                );
            } else {
                eprintln!(
                    "Initialized uniform noise container at {} ({} bytes, {} blocks)",
                    out.display(),
                    container.len(),
                    total_blocks
                );
                eprintln!("Hundi Challenge: {chal}");
                if let Some(eph) = maybe_eph_sec {
                    let eph_tok = Zeroizing::new(format!("fubuki-sec-v1:{}", hex::encode(*eph)));
                    eprintln!(
                        "Ephemeral Sealing Key (use with --eph-key-env for dual pubkey sealing, then discard): {}",
                        eph_tok.as_str()
                    );
                }
            }
        }

        Commands::Seal {
            volume,
            in_path,
            pass_env,
            pubkey,
            authorized_keys,
            eph_key_env,
            rekey_preamble,
            hybrid_pass,
            decoy_mode,
            kdf_profile,
        } => {
            let mut container = std::fs::read(&volume)
                .with_context(|| format!("failed to read container {}", volume.display()))?;
            let payload = read_input_bytes(&in_path)?;
            let profile: KdfProfile = kdf_profile.into();

            let (_anchor, blocks_used) = if let Some(pk_spec) = pubkey {
                let recip_pub = parse_public_key_spec(&pk_spec, Some(&authorized_keys))?;
                let eph_sk = match eph_key_env.as_deref() {
                    Some(var) => {
                        let raw = resolve_credential_raw(Some(var), "")?;
                        Some(parse_secret_key_spec(&raw)?)
                    }
                    None => {
                        if !rekey_preamble {
                            return Err(anyhow!(
                                "seal --pubkey without --eph-key-env would overwrite container S_0[0..64] and invalidate existing slots; pass --eph-key-env <VAR> or --rekey-preamble to confirm single-slot rekeying"
                            ));
                        }
                        None
                    }
                };
                let hybrid_pw = if let Some(var) = pass_env.as_deref() {
                    Some(resolve_credential_raw(Some(var), "")?)
                } else if hybrid_pass {
                    Some(resolve_credential_raw(
                        None,
                        "Hybrid slot passphrase (paired with pubkey): ",
                    )?)
                } else {
                    None
                };
                seal_volume_for_pubkey_bytes(
                    &mut container,
                    &recip_pub,
                    eph_sk.as_ref(),
                    hybrid_pw.as_deref().map(String::as_bytes),
                    &payload,
                    decoy_mode,
                    profile,
                )?
            } else {
                let cred_raw = resolve_credential_raw(
                    pass_env.as_deref(),
                    "Slot credential (passphrase, fubuki-hs-v1:<hex>, or pass+fubuki-hs-v1:<hex>): ",
                )?;
                let cred = parse_credential_input(&cred_raw)?;
                seal_volume_with_modality_bytes(
                    &mut container,
                    cred.passphrase.as_deref().map(Vec::as_slice),
                    cred.handshake.as_deref(),
                    &payload,
                    decoy_mode,
                    profile,
                )?
            };

            write_output_bytes(&volume, &container)?;
            eprintln!(
                "Sealed {} bytes across {} contiguous stride block(s) into {}",
                payload.len(),
                blocks_used,
                volume.display()
            );
        }

        Commands::Unlock {
            volume,
            out,
            pass_env,
            kdf_profile,
        } => {
            let container = std::fs::read(&volume)
                .with_context(|| format!("failed to read container {}", volume.display()))?;
            let cred_raw = resolve_credential_raw(
                pass_env.as_deref(),
                "Volume credential (passphrase, fubuki-hs-v1:<hex>, or pass+fubuki-hs-v1:<hex>): ",
            )?;
            let cred = parse_credential_input(&cred_raw)?;
            let profile: KdfProfile = kdf_profile.into();

            let slot = unlock_volume_with_modality_bytes(
                &container,
                cred.passphrase.as_deref().map(Vec::as_slice),
                cred.handshake.as_deref(),
                profile,
            )?;
            write_output_bytes(&out, &slot.payload)?;
        }

        Commands::AuditEntropy { target, json } => {
            let data = std::fs::read(&target)
                .with_context(|| format!("failed to read target {}", target.display()))?;
            let report = audit_bytes(&data);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Target: {}", target.display());
                println!("Bytes: {}", report.total_bytes);
                println!(
                    "Shannon Entropy H(X): {:.6} bits/byte",
                    report.shannon_entropy_bits_per_byte
                );
                println!(
                    "Pearson Chi-Square: {:.3} (p = {:.6})",
                    report.chi_square_stat, report.chi_square_p_value
                );
                println!("Serial Correlation: {:.6}", report.serial_correlation);
                if report.detected_magic_signatures.is_empty() {
                    println!("Magic Signatures: none (data / uniform noise)");
                } else {
                    println!(
                        "Magic Signatures: {}",
                        report.detected_magic_signatures.join(", ")
                    );
                }
                println!(
                    "Indistinguishability Verdict: {}",
                    if report.is_indistinguishable_noise {
                        "PASS"
                    } else {
                        "FAIL"
                    }
                );
            }
            if !report.is_indistinguishable_noise {
                std::process::exit(1);
            }
        }

        Commands::Tui { target } => {
            let app = FubukiTuiApp::from_path(target.as_deref())?;
            run_interactive_tui(app)?;
        }
    }

    Ok(())
}
