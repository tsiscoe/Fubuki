# Contributing to `fubuki`

## Engineering Rules
1. **Zero `unsafe`:** `#![forbid(unsafe_code)]` is non-negotiable across all modules and tests.
2. **Memory Hygiene:** Any struct holding keys, passphrases, or unsealed plaintext must derive `Zeroize` / `ZeroizeOnDrop` or reside inside `Zeroizing<T>`.
3. **No Panics in Production Paths:** Avoid `.unwrap()` / `.expect()` outside tests (`clippy::unwrap_used` is active).
4. **Statistical & Property Invariants:** Changes to `winnow` or `volume` must continue passing all `proptest` losslessness, single-bit tamper rejection, 10,000-sample Elligator2 uniformity, and `TestBackend` TUI snapshot tests.

## Pre-PR Gate

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```
