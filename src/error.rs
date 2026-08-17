//! Error types shared by the library and CLI.

use std::path::PathBuf;

/// Result alias for `tripwire-seed` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can be returned without exposing secret material.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The operating system random source failed.
    #[error("the operating system random source failed")]
    Random(#[from] getrandom::Error),

    /// A BIP39 mnemonic was invalid.
    #[error("invalid BIP39 mnemonic: {0}")]
    Bip39(#[from] bip39::Error),

    /// BIP32 key derivation failed.
    #[error("BIP32 derivation failed: {0}")]
    Bip32(#[from] bitcoin::bip32::Error),

    /// A derivation path could not be parsed.
    #[error("invalid derivation path: {0}")]
    DerivationPath(String),

    /// An output descriptor used a character outside the BIP380 checksum set.
    #[error("invalid BIP380 descriptor character {character:?} at byte position {position}")]
    InvalidDescriptorCharacter {
        /// Zero-based byte position in the descriptor.
        position: usize,
        /// Unsupported character.
        character: char,
    },

    /// A descriptor body already contained a checksum separator.
    #[error("descriptor body already contains a checksum separator")]
    DescriptorAlreadyContainsChecksum,

    /// Serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// One or more deterministic public-vector checks failed.
    #[error("deterministic public-vector self-test failed ({failed} checks)")]
    SelfTestFailed {
        /// Number of known-answer checks that failed.
        failed: usize,
    },

    /// QR generation failed.
    #[error("SeedQR generation failed: {0}")]
    Qr(#[from] qrcode::types::QrError),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The passphrase word count was outside the supported range.
    #[error("passphrase word count must be between {min} and {max}; got {actual}")]
    PassphraseWordCount {
        /// Minimum accepted value.
        min: usize,
        /// Maximum accepted value.
        max: usize,
        /// Supplied value.
        actual: usize,
    },

    /// Dice input contained an invalid character.
    #[error("dice input may contain only digits 1 through 6 and whitespace")]
    InvalidDice,

    /// More accepted dice groups are required.
    #[error(
        "not enough accepted dice groups: {accepted}/{required} words selected; add more rolls"
    )]
    InsufficientDice {
        /// Number of accepted groups.
        accepted: usize,
        /// Number required.
        required: usize,
    },

    /// The output path already exists.
    #[error("refusing to overwrite existing path: {0}")]
    OutputExists(PathBuf),

    /// A watch-only reference exceeded the bounded input size.
    #[error("watch-only reference exceeds the {max}-byte safety limit")]
    WatchOnlyTooLarge {
        /// Maximum accepted watch-only input size.
        max: usize,
    },

    /// A watch-only reference does not match the supported schema and policy.
    #[error("watch-only reference uses an unsupported schema or account standard")]
    UnsupportedWatchOnlyFormat,

    /// A supported watch-only reference contains inconsistent public metadata.
    #[error("watch-only reference is internally inconsistent")]
    InvalidWatchOnlyReference,

    /// A supplied watch-only fingerprint was not 64 hexadecimal characters.
    #[error("watch-only fingerprint must be exactly 64 hexadecimal characters")]
    InvalidWatchOnlyFingerprint,

    /// A watch-only reference did not match its independently retained fingerprint.
    #[error("watch-only reference fingerprint verification failed")]
    WatchOnlyFingerprintMismatch,

    /// Re-derived public wallet data did not exactly match the reference.
    #[error("watch-only recovery verification failed")]
    WatchOnlyMismatch,

    /// A secret export is unavailable on this platform.
    #[error("plaintext secret export is unsupported on this platform in version 0.1")]
    SecretExportUnsupported,

    /// A CLI operation required an interactive terminal.
    #[error("this operation requires an interactive terminal")]
    InteractiveTerminalRequired,

    /// The operator did not enter the exact confirmation phrase.
    #[error("confirmation did not match; no secret was displayed or written")]
    ConfirmationFailed,

    /// A generated backup was not re-entered exactly.
    #[error("backup verification failed; mnemonic and passphrase must be copied exactly")]
    BackupVerificationFailed,
}
