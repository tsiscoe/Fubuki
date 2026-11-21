# Architecture (`fubuki` v0.2.0)

## 1. Crate Security Posture
- **Rust 2024 Edition** with `#![forbid(unsafe_code)]` enforced at crate root (`src/lib.rs`, `src/main.rs`) and in `[lints.rust]`.
- **Deterministic Memory Scrubbing:** Passphrases and handshake credentials (`Zeroizing<String>`), plaintext payloads (`Zeroizing<Vec<u8>>`), `SlotKeys` (`ZeroizeOnDrop`), `UnlockedSlot` (`ZeroizeOnDrop`), and intermediate wheat frames (`Zeroize`) wipe before drop.
- **Constant-Time Verification:** Mode A MAC verification and PKCS#7 tail stripping use `subtle::ConstantTimeEq`. Mode B anchor verification evaluates a single branchless `Argon2id` + `BLAKE3` + `XChaCha20-Poly1305` path across all credential modalities.

## 2. Mode A: Keyed BLAKE3 Chaffing & Winnowing (`src/winnow/`)
- **Seed:** `16B` uniform `N_s` via `OsRng`.
- **Framing:** Input $M$ is PKCS#7-padded into $L \ge 1$ 16-byte symbols $w_0 \dots w_{L-1}$.
- **Authentication:** Non-final wheat frames tag `"fubuki.wheat.v1" || N_s || LE64(s_i) || w_i`; the final frame $w_{L-1}$ tags `"fubuki.wheat.eos.v1" || N_s || LE64(s_{L-1}) || w_{L-1}`.
- **Chaff & Blinding:** Each authentic frame emits $\rho \in [1, 255]$ chaff tuples $(\tilde{w}_{i,j} \neq w_i,\; \tilde{m}_{i,j} \xleftarrow{\$} \{0,1\}^{128})$, shuffled via CSPRNG Fisher-Yates and masked at physical wire offset `slot_idx` by $\hat{s}_i = s_i \oplus \text{Trunc}_{64}(\text{BLAKE3}(N_s \parallel \text{LE64}(\text{slot\_idx})))$.
- **Out-of-Band TTY / Pubkey KDF:** When `FUBUKI_MAC_KEY` is unset, `scatter` / `winnow` prompt via controlling terminal (`CONIN$` / `/dev/tty`) without disturbing `stdin`/`stdout` pipes, and accept `fubuki-hs-v1:<hex>` or `<pass>+fubuki-hs-v1:<hex>` tokens.

## 3. Mode B: Elligator2 Coercion Volumes & `Mahajani` Pubkey Handshake (`src/volume/`, `src/pubkey.rs`)
- **Container Layout:** `64B` uniform preamble $S_0 = \mathcal{E}^{-1}(R)[32] \parallel \text{Salt}_{256}[32]$ followed by $B$ fixed-stride `4096B` blocks (`24B XNonce || 4056B ciphertext || 16B Poly1305 tag`).
- **Two-Branch `Elligator2` (`fe25519.rs`, `elligator.rs`):** Constant-time $5 \times 51$-bit $\mathbb{F}_{2^{255}-19}$ arithmetic sampling both preimage branches $r_1, r_2 \in [0, (p-1)/2]$ equally with CSPRNG top-2 padding bits $b_{254}, b_{255}$.
- **`Mahajani` Pubkey Bridge (`src/pubkey.rs` & `tools/fetch_keyserver.py`):** Resolves `<user>.asc` / `.pgp` / `.pub` keys from `./authorized_keys/`, fetches keys via HTTPS-only HKP (`tools/fetch_keyserver.py`), and computes deterministic `X25519(sk_user, elligator2_decode(S_0[0..32]))` handshakes (`fubuki-hs-v1:<64hex>`) submitted directly as the unlock credential without storing any public keys inside the container. Compound `init_and_seal_dual_pubkeys_bytes` (`--duress-in` / `--sov-in`) seals both pubkey slots in one RAM pass and zeroizes the ephemeral sealing key before exiting.
- **Three-Modality Key Expansion (`src/kdf.rs`):** Supports Passphrase (`P`), Pure Pubkey Handshake (`fubuki.modality.handshake.v1`), and Hybrid (`fubuki.modality.hybrid.v1`), stretching via `Argon2id(64 MiB, t=3, p=4)` and expanding `(K_enc, K_hdr, K_loc)` via keyed BLAKE3; anchor index $\beta_0 = \text{LE64}(\text{BLAKE3}_{K_{\text{loc}}}(\text{"fubuki.slot.anchor.v1"})) \bmod (B - B_{\text{guard}})$.

## 4. Operational Boundaries
- Plausible deniability holds against single-snapshot forensic capture. Multi-snapshot block diffs across independent mutations of Slot 1 without updating Slot 0 leak changed sectors; re-encrypting the full container on update prevents differential sector correlation.
- Slots sealed with `--decoy-mode` enforce a `25%` (`total_blocks / 4`) payload span ceiling and disallow crossing `B_decoy`.
