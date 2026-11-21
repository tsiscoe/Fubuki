# Installation (`fubuki` v0.1.0)

## Prerequisites
- Rust toolchain `1.99.1` or newer (`edition = "2024"`).

## Build from Source

```bash
git clone https://github.com/tsiscoe/Fubuki.git
cd Fubuki
cargo build --release
```

The release binary is produced at `target/release/fubuki` (`target\release\fubuki.exe` on Windows).

## Verification Suite

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```
