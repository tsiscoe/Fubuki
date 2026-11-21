# Changelog

## v0.2.0 — 2026-11-20
- Added `Mahajani`-style asymmetric pubkey handshake authentication modality (`src/pubkey.rs`) across Mode A, Mode B, and the 3-pane `ratatui` v0.30 TUI (`fubuki tui`), plus `tools/fetch_keyserver.py` HTTPS HKP keyfetcher (`authorized_keys/*.asc`).
- Added `fubuki keygen`, `fubuki challenge`, `fubuki handshake`, and one-shot compound `init-volume --duress-pubkey --sov-pubkey --duress-in --sov-in` (`init_and_seal_dual_pubkeys_bytes`, keeping the ephemeral sealing key strictly inside RAM before zeroizing).
- Unified `derive_slot_keys_flexible` across three modalities (`Passphrase`, `PubkeyHandshake`, `HybridPassphraseHandshake`) plus `init_volume_dual_pubkeys_bytes` and `seal_volume_for_pubkey_bytes`.
- Added out-of-band TTY (`CONIN$` / `/dev/tty`) credential prompting for `scatter` and `winnow` when `FUBUKI_MAC_KEY` is unset, keeping `stdin`/`stdout` pipes pure without `export`.
- Extended `prop_uniformity` and `prop_winnow` with OpenPGP `.asc` lookup, dual-pubkey coercion isolation, hybrid PIN enforcement, Mode A handshake MACs, and TUI Hundi gate tests.

## v0.1.0 — 2026-11-20
- Initial implementation of `fubuki` in pure Rust 2024 Edition (`#![forbid(unsafe_code)]`).
- Added Mode A cipherless keyed-BLAKE3 packet winnowing (`scatter` / `winnow`) and Mode B Elligator2 headerless coercion-resistant dual volumes (`init-volume` / `seal` / `unlock`).
- Added built-in statistical auditor (`audit-entropy`) and 3-pane `ratatui` v0.30 TUI (`fubuki tui`).
