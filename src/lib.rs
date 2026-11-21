#![forbid(unsafe_code)]
//! **Fubuki** (`fubuki`) — Cipherless Keyed-BLAKE3 Winnowing & Elligator2 Coercion-Resistant Dual Volumes.
//!
//! Built for pure-Rust 2024 compliance (`#![forbid(unsafe_code)]`) with deterministic
//! `ZeroizeOnDrop` key hygiene across both transport and custody modes:
//! - **Mode A (`winnow`):** Ronald Rivest's *Chaffing and Winnowing* paradigm using zero
//!   encryption primitives—only keyed BLAKE3 MACs, PKCS#7-padded 16-byte frames, authenticated
//!   EOS domain separation, and sequence index blinding.
//! - **Mode B (`volume`):** Fixed-stride 4 KiB coercion-resistant containers wrapped in
//!   two-branch Curve25519 `Elligator2` uniform preambles and `XChaCha20-Poly1305` slot blocks,
//!   supporting branchless single-formula anchor resolution for decoy and sovereign slots.

pub mod audit;
pub mod cli;
pub mod kdf;
pub mod pubkey;
pub mod tui;
pub mod volume;
pub mod winnow;

use thiserror::Error;

/// Unified error taxonomy for `fubuki` winnowing, coercion volumes, and entropy auditing.
#[derive(Debug, Error)]
pub enum FubukiError {
    /// Wire stream length is smaller than the 16-byte seed or not aligned to 40-byte tuples.
    #[error("invalid winnow wire alignment: {len} bytes (expected 16 + k * {tuple_size})")]
    InvalidWireAlignment { len: usize, tuple_size: usize },

    /// An expected sequence frame had zero valid MAC tuples after winnowing.
    #[error("missing or tampered sequence frame {0}")]
    MissingSequenceFrame(u64),

    /// Multiple distinct authentic wheat frames claimed the same sequence index.
    #[error("duplicate authentic wheat frame at sequence index {0}")]
    DuplicateSequenceFrame(u64),

    /// Stream terminated without an authenticated end-of-stream (`EOS`) sentinel frame.
    #[error("stream ended without an authenticated end-of-stream sentinel")]
    MissingEndOfStream,

    /// Reconstructed final frame contained invalid PKCS#7 padding.
    #[error("invalid PKCS#7 frame padding in final wheat frame")]
    InvalidFramePadding,

    /// Invalid chaff-to-wheat ratio outside `[1, 255]`.
    #[error("invalid chaff-to-wheat ratio {0}; expected 1..=255")]
    InvalidRatio(u8),

    /// Generic constant-time authentication error for Mode B volume unlocks.
    #[error("volume authentication failed")]
    AuthenticationFailed,

    /// Invalid volume size, block alignment, or decoy partition boundary.
    #[error("invalid volume geometry: {0}")]
    ContainerGeometryError(String),

    /// Payload exceeds total capacity or the enforced decoy block ceiling.
    #[error("payload requires {needed_blocks} blocks, exceeding slot ceiling {max_blocks}")]
    PayloadExceedsCapacity {
        needed_blocks: usize,
        max_blocks: usize,
    },

    /// Dual-slot anchor rejection sampling failed to find non-overlapping spans within budget.
    #[error("failed to sample non-overlapping dual-slot preamble within retry budget")]
    SlotOverlapExhausted,

    /// Key loading, parsing, or KDF invocation failed.
    #[error("key resolution error: {0}")]
    KeyResolutionError(String),

    /// Underlying filesystem or stream I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type FubukiResult<T> = Result<T, FubukiError>;
