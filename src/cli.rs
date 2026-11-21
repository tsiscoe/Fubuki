//! `clap` v4 Unix CLI surface for `fubuki`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::kdf::KdfProfile;

/// Key stretching profile selector for Mode B coercion volumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KdfProfileArg {
    /// Production floor: Argon2id (`64 MiB`, `t=3`, `p=4`).
    Production,
    /// Fast profile (`4 MiB`, `t=1`, `p=1`) for local benchmarking/testing.
    Fast,
}

impl From<KdfProfileArg> for KdfProfile {
    fn from(arg: KdfProfileArg) -> Self {
        match arg {
            KdfProfileArg::Production => KdfProfile::production(),
            KdfProfileArg::Fast => KdfProfile::fast(),
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "fubuki",
    version,
    about = "Cipherless keyed-BLAKE3 winnowing & Elligator2 coercion-resistant dual volumes with Mahajani-style pubkey handshake auth"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generate a Curve25519 Hundi keypair and OpenPGP `.asc` file for `authorized_keys/` registries.
    Keygen {
        /// Operator username (`<user>.asc` written under `--out-dir`).
        #[arg(long)]
        user: String,

        /// Directory storing OpenPGP `.asc` public keys (Mahajani convention).
        #[arg(long, default_value = "authorized_keys")]
        out_dir: PathBuf,

        /// Emit machine-readable JSON output.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Print the 32-byte `Elligator2` Hundi Challenge token (`fubuki-chal-v1:...`) of a volume.
    Challenge {
        /// Path to the coercion volume container.
        target: PathBuf,

        /// Emit machine-readable JSON output.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Compute the user's half of the `Mahajani`-style handshake (`fubuki-hs-v1:...`) for `unlock`/`winnow`/`tui`.
    Handshake {
        /// Container file path or raw `fubuki-chal-v1:<64hex>` challenge string.
        #[arg(long)]
        challenge: String,

        /// Environment variable carrying `fubuki-sec-v1:<64hex>` (prompts masked via TTY if omitted).
        #[arg(long)]
        secret_env: Option<String>,

        /// Optional environment variable holding hybrid passphrase (`<pass>+fubuki-hs-v1:<64hex>`).
        #[arg(long)]
        pass_env: Option<String>,

        /// Prompt interactively for an optional hybrid passphrase to append to the handshake token.
        #[arg(long, default_value_t = false)]
        hybrid_pass: bool,
    },

    /// Mode A: Scatter input stream into keyed-BLAKE3 wheat + CSPRNG chaff tuples (zero encryption).
    Scatter {
        /// Number of synthetic chaff tuples generated per authentic wheat frame (1..=255).
        #[arg(long, default_value_t = 7)]
        ratio: u8,

        /// Environment variable carrying a MAC key, passphrase, or `fubuki-hs-v1:<64hex>` credential.
        #[arg(long, default_value = "FUBUKI_MAC_KEY")]
        key_env: String,

        /// Optional direct hex-encoded 32-byte MAC key (for non-interactive testing).
        #[arg(long)]
        key_hex: Option<String>,

        /// Optional recipient public key (`<user>`, `.asc` path, `fubuki-pub-v1:<hex>`, or PGP armor).
        #[arg(long)]
        pubkey: Option<String>,

        /// Directory storing OpenPGP `.asc`/`.pgp`/`.pub` files for username resolution.
        #[arg(long, default_value = "authorized_keys")]
        authorized_keys: PathBuf,

        /// Input file path (or `-` for stdin).
        #[arg(long = "in", short = 'i', default_value = "-")]
        in_path: PathBuf,

        /// Output file path (or `-` for stdout).
        #[arg(long = "out", short = 'o', default_value = "-")]
        out_path: PathBuf,
    },

    /// Mode A: Winnow wheat frames from chaff stream in constant time using keyed BLAKE3.
    Winnow {
        /// Environment variable carrying a MAC key, passphrase, or `fubuki-hs-v1:<64hex>` credential.
        #[arg(long, default_value = "FUBUKI_MAC_KEY")]
        key_env: String,

        /// Optional direct hex-encoded 32-byte MAC key.
        #[arg(long)]
        key_hex: Option<String>,

        /// Input stream file path (or `-` for stdin).
        #[arg(long = "in", short = 'i', default_value = "-")]
        in_path: PathBuf,

        /// Output file path (or `-` for stdout).
        #[arg(long = "out", short = 'o', default_value = "-")]
        out_path: PathBuf,
    },

    /// Mode B: Provision a headerless uniform noise container (`64 + B * 4096` bytes).
    InitVolume {
        /// Target payload capacity (e.g., `64M`, `1M`, `256K`).
        #[arg(long)]
        size: String,

        /// Destination container file path.
        #[arg(long, short = 'o')]
        out: PathBuf,

        /// Maximum decoy partition span (defaults to 25% of volume capacity).
        #[arg(long)]
        decoy_max: Option<String>,

        /// Optional environment variable holding duress passphrase for guaranteed dual-slot S_0 separation.
        #[arg(long)]
        duress_pass_env: Option<String>,

        /// Optional environment variable holding sovereign passphrase for guaranteed dual-slot S_0 separation.
        #[arg(long)]
        sov_pass_env: Option<String>,

        /// Optional duress public key (`<user>`, `.asc` path, `fubuki-pub-v1:<hex>`, or armor) for dual-pubkey separation.
        #[arg(long)]
        duress_pubkey: Option<String>,

        /// Optional sovereign public key (`<user>`, `.asc` path, `fubuki-pub-v1:<hex>`, or armor) for dual-pubkey separation.
        #[arg(long)]
        sov_pubkey: Option<String>,

        /// Optional decoy payload path for one-shot compound dual-pubkey sealing (ephemeral key stays strictly in RAM).
        #[arg(long)]
        duress_in: Option<PathBuf>,

        /// Optional sovereign payload path for one-shot compound dual-pubkey sealing (ephemeral key stays strictly in RAM).
        #[arg(long)]
        sov_in: Option<PathBuf>,

        /// Directory storing OpenPGP `.asc`/`.pgp`/`.pub` files for username resolution.
        #[arg(long, default_value = "authorized_keys")]
        authorized_keys: PathBuf,

        /// Emit machine-readable JSON metadata (including one-time ephemeral sealing key if dual-pubkey).
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Argon2id stretching profile.
        #[arg(long, value_enum, default_value_t = KdfProfileArg::Production)]
        kdf_profile: KdfProfileArg,
    },

    /// Mode B: Seal a payload into an initialized container using Passphrase, Pubkey Handshake, or Hybrid modality.
    Seal {
        /// Path to the coercion container file.
        volume: PathBuf,

        /// Payload input file path (or `-` for stdin).
        #[arg(long = "in", short = 'i')]
        in_path: PathBuf,

        /// Environment variable holding slot credential (or hybrid passphrase when `--pubkey` is set).
        #[arg(long)]
        pass_env: Option<String>,

        /// Optional recipient public key (`<user>`, `.asc` path, `fubuki-pub-v1:<hex>`, or PGP armor).
        #[arg(long)]
        pubkey: Option<String>,

        /// Directory storing OpenPGP `.asc`/`.pgp`/`.pub` files for username resolution.
        #[arg(long, default_value = "authorized_keys")]
        authorized_keys: PathBuf,

        /// Optional environment variable holding the volume's ephemeral sealing secret (`fubuki-sec-v1:...`) when sealing multiple pubkey slots.
        #[arg(long)]
        eph_key_env: Option<String>,

        /// Prompt interactively for an additional hybrid passphrase when `--pubkey` is active.
        #[arg(long, default_value_t = false)]
        hybrid_pass: bool,

        /// Enforce deterministic 25% block ceiling so decoy writes never spill into sovereign slack.
        #[arg(long, default_value_t = false)]
        decoy_mode: bool,

        /// Argon2id stretching profile.
        #[arg(long, value_enum, default_value_t = KdfProfileArg::Production)]
        kdf_profile: KdfProfileArg,
    },

    /// Mode B: Unlock and extract a slot via constant-time branchless verification.
    Unlock {
        /// Path to the coercion container file.
        volume: PathBuf,

        /// Output file path (or `-` for raw binary stdout).
        #[arg(long = "out", short = 'o', default_value = "-")]
        out: PathBuf,

        /// Environment variable holding credential (`passphrase`, `fubuki-hs-v1:<hex>`, or `pass+fubuki-hs-v1:<hex>`).
        #[arg(long)]
        pass_env: Option<String>,

        /// Argon2id stretching profile.
        #[arg(long, value_enum, default_value_t = KdfProfileArg::Production)]
        kdf_profile: KdfProfileArg,
    },

    /// Audit a stream or container for Shannon entropy, chi-square uniformity, and zero magic headers.
    AuditEntropy {
        /// Target file path to inspect.
        target: PathBuf,

        /// Emit machine-readable JSON telemetry.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Launch the 3-pane `ratatui` v0.30 interactive inspection & gate console.
    Tui {
        /// Optional volume or winnowed stream path to inspect immediately.
        #[arg(long)]
        target: Option<PathBuf>,
    },
}
