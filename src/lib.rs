//! Security-focused building blocks for the `tripwire-seed` CLI.
//!
//! The library deliberately exposes only public wallet metadata. Secret display
//! and secret-file export are explicit CLI operations with separate warnings.

#![forbid(unsafe_code)]

pub mod audit;
pub mod error;
pub mod export;
pub mod passphrase;
pub mod wallet;

pub use error::{Error, Result};

/// The default word count for a generated passphrase.
///
/// Each word is sampled uniformly from the 2,048-word English BIP39 list, so
/// 12 independently sampled words carry 132 bits of construction entropy.
pub const DEFAULT_PASSPHRASE_WORDS: usize = 12;

/// The fixed word count for the base BIP39 mnemonic in version 0.1.
pub const MNEMONIC_WORDS: usize = 12;
