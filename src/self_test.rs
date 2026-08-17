//! Deterministic known-answer checks for packaged binaries and independent review.

use bip39::{Language, Mnemonic};
use bitcoin::hex::DisplayHex;
use serde::Serialize;

use crate::{
    Result,
    descriptor::with_checksum,
    fingerprint::watch_only_fingerprint,
    passphrase::{DiceAccumulator, GenerationSource},
    wallet::{WalletNetwork, derive_tripwire_summary, validate_tripwire_summary},
};

/// Stable schema identifier for machine-readable self-test reports.
pub const SELF_TEST_SCHEMA: &str = "tripwire-seed/self-test/v1";

const PUBLIC_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PUBLIC_BIP39_PASSPHRASE: &str = "TREZOR";
const EXPECTED_BIP39_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
const EXPECTED_ACCOUNT_XPUB: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
const EXPECTED_FIRST_ADDRESS: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const EXPECTED_RECEIVE_DESCRIPTOR: &str = "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#afwvtk2s";
const EXPECTED_CHANGE_DESCRIPTOR: &str = "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#vatdkr6g";
const EXPECTED_WATCH_ONLY_FINGERPRINT: &str =
    "4589b151544e36e6c9efa228654224d010373b340eb9b9e1f31ac024ca56383f";

/// Result of one deterministic public-vector check.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SelfTestCheck {
    name: &'static str,
    passed: bool,
}

impl SelfTestCheck {
    fn new(name: &'static str, passed: bool) -> Self {
        Self { name, passed }
    }

    /// Return the stable check name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Return whether the known-answer comparison passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }
}

/// Machine-readable deterministic self-test report.
///
/// The report contains only check names, version metadata, and boolean results.
/// It never includes a user mnemonic, passphrase, seed, xpub, descriptor, or
/// address. Every value used internally is an established public test vector.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SelfTestReport {
    schema: &'static str,
    crate_version: &'static str,
    public_vectors_only: bool,
    passed: bool,
    checks: Vec<SelfTestCheck>,
}

impl SelfTestReport {
    /// Return the report schema identifier.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    /// Return the package version that executed the checks.
    #[must_use]
    pub const fn crate_version(&self) -> &'static str {
        self.crate_version
    }

    /// Return true because version 1 executes only fixed public vectors.
    #[must_use]
    pub const fn uses_only_public_vectors(&self) -> bool {
        self.public_vectors_only
    }

    /// Return true only when every check passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }

    /// Return the ordered list of known-answer checks.
    #[must_use]
    pub fn checks(&self) -> &[SelfTestCheck] {
        &self.checks
    }

    /// Return the number of failed checks.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.checks.iter().filter(|check| !check.passed()).count()
    }
}

/// Run deterministic checks over public BIP39, BIP84, and BIP380 vectors.
///
/// This verifies the packaged binary's current implementation and dependency
/// behavior. It does not authenticate the binary, evaluate the operating-system
/// random source, prove reproducible compilation, or replace independent review.
///
/// # Errors
///
/// Returns an error if a fixed public vector cannot be parsed or an underlying
/// derivation, descriptor, dice, serialization, or fingerprint operation fails.
pub fn run_self_test() -> Result<SelfTestReport> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, PUBLIC_MNEMONIC)?;
    let seed = mnemonic.to_seed(PUBLIC_BIP39_PASSPHRASE);
    let summary = derive_tripwire_summary(&mnemonic, "", WalletNetwork::Bitcoin)?;
    let descriptor_vector = with_checksum("raw(deadbeef)")?;
    let fingerprint = watch_only_fingerprint(&summary)?;

    let mut dice = DiceAccumulator::new(6)?;
    dice.push_rolls("66666 11111 11111 11111 11111 11111 11111")?;
    let dice_metadata = dice.rejected_groups() == 1 && dice.accepted_words() == 6;
    let generated = dice.finish()?;
    let dice_output = generated.source() == GenerationSource::Dice
        && generated.entropy_bits() == 66
        && generated.expose() == "abandon-abandon-abandon-abandon-abandon-abandon";

    let checks = vec![
        SelfTestCheck::new(
            "bip39-seed",
            seed.as_hex().to_string() == EXPECTED_BIP39_SEED,
        ),
        SelfTestCheck::new(
            "bip84-account-xpub",
            summary.decoy.account_xpub == EXPECTED_ACCOUNT_XPUB,
        ),
        SelfTestCheck::new(
            "bip84-first-receive-address",
            summary.decoy.first_receive_address == EXPECTED_FIRST_ADDRESS,
        ),
        SelfTestCheck::new(
            "bip84-receive-descriptor",
            summary.decoy.receive_descriptor == EXPECTED_RECEIVE_DESCRIPTOR,
        ),
        SelfTestCheck::new(
            "bip84-change-descriptor",
            summary.decoy.change_descriptor == EXPECTED_CHANGE_DESCRIPTOR,
        ),
        SelfTestCheck::new(
            "bip380-descriptor-checksum",
            descriptor_vector == "raw(deadbeef)#89f8spxm",
        ),
        SelfTestCheck::new("dice-rejection-sampling", dice_metadata && dice_output),
        SelfTestCheck::new(
            "watch-only-semantic-validation",
            validate_tripwire_summary(&summary).is_ok(),
        ),
        SelfTestCheck::new(
            "watch-only-fingerprint",
            fingerprint == EXPECTED_WATCH_ONLY_FINGERPRINT,
        ),
    ];
    let passed = checks.iter().all(SelfTestCheck::passed);

    Ok(SelfTestReport {
        schema: SELF_TEST_SCHEMA,
        crate_version: env!("CARGO_PKG_VERSION"),
        public_vectors_only: true,
        passed,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_vector_report_passes() {
        let report =
            run_self_test().unwrap_or_else(|error| unreachable!("public vectors execute: {error}"));
        assert!(report.passed());
        assert_eq!(report.failed_count(), 0);
        assert_eq!(report.checks().len(), 9);
        assert_eq!(report.schema(), SELF_TEST_SCHEMA);
        assert!(report.uses_only_public_vectors());
    }

    #[test]
    fn serialized_report_contains_no_vector_material() {
        let report =
            run_self_test().unwrap_or_else(|error| unreachable!("public vectors execute: {error}"));
        let encoded = serde_json::to_string(&report)
            .unwrap_or_else(|error| unreachable!("report serializes: {error}"));
        for excluded in [
            PUBLIC_MNEMONIC,
            PUBLIC_BIP39_PASSPHRASE,
            EXPECTED_BIP39_SEED,
            EXPECTED_ACCOUNT_XPUB,
            EXPECTED_RECEIVE_DESCRIPTOR,
            EXPECTED_CHANGE_DESCRIPTOR,
            EXPECTED_FIRST_ADDRESS,
        ] {
            assert!(!encoded.contains(excluded));
        }
    }
}
