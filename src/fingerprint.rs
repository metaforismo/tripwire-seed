//! Domain-separated fingerprints for versioned watch-only references.

use bitcoin::hashes::{Hash, sha256};

use crate::{Error, Result, wallet::TripwireSummary};

const WATCH_ONLY_FINGERPRINT_DOMAIN: &[u8] = b"tripwire-seed/watch-only-fingerprint/v1\0";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Compute the canonical SHA-256 fingerprint for a watch-only summary.
///
/// The fingerprint hashes a domain separator followed by compact JSON emitted
/// from the strict version 1 Rust data model. It contains no secret wallet
/// material, but it commits to every public field in the summary.
///
/// # Errors
///
/// Returns an error when serialization fails.
pub fn watch_only_fingerprint(summary: &TripwireSummary) -> Result<String> {
    let encoded = serde_json::to_vec(summary)?;
    let mut committed = Vec::with_capacity(WATCH_ONLY_FINGERPRINT_DOMAIN.len() + encoded.len());
    committed.extend_from_slice(WATCH_ONLY_FINGERPRINT_DOMAIN);
    committed.extend_from_slice(&encoded);
    let digest = sha256::Hash::hash(&committed).to_byte_array();
    Ok(encode_lower_hex(&digest))
}

/// Compare a separately retained fingerprint with a decoded watch-only summary.
///
/// Upper- or lower-case hexadecimal input is accepted. This verifies only that
/// the reference matches the supplied fingerprint; trust still depends on the
/// fingerprint having been stored or communicated through an independent,
/// authenticated channel.
///
/// # Errors
///
/// Returns [`Error::InvalidWatchOnlyFingerprint`] for malformed input or
/// [`Error::WatchOnlyFingerprintMismatch`] when the reference differs.
pub fn verify_watch_only_fingerprint(expected: &str, summary: &TripwireSummary) -> Result<()> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::InvalidWatchOnlyFingerprint);
    }

    let actual = watch_only_fingerprint(summary)?;
    if expected.eq_ignore_ascii_case(&actual) {
        Ok(())
    } else {
        Err(Error::WatchOnlyFingerprintMismatch)
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(LOWER_HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use bip39::{Language, Mnemonic};

    use super::*;
    use crate::wallet::{WalletNetwork, derive_tripwire_summary};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn summary() -> TripwireSummary {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        derive_tripwire_summary(&mnemonic, "correct protected value", WalletNetwork::Bitcoin)
            .unwrap_or_else(|error| unreachable!("valid derivation: {error}"))
    }

    #[test]
    fn fingerprint_is_deterministic_lower_hex_and_domain_separated() {
        let summary = summary();
        let first = watch_only_fingerprint(&summary)
            .unwrap_or_else(|error| unreachable!("summary serializes: {error}"));
        let second = watch_only_fingerprint(&summary)
            .unwrap_or_else(|error| unreachable!("summary serializes: {error}"));
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(first, first.to_ascii_lowercase());

        let plain_json = serde_json::to_vec(&summary)
            .unwrap_or_else(|error| unreachable!("summary serializes: {error}"));
        let plain_digest = sha256::Hash::hash(&plain_json).to_byte_array();
        assert_ne!(first, encode_lower_hex(&plain_digest));
    }

    #[test]
    fn every_public_field_is_committed() {
        let original = summary();
        let original_fingerprint = watch_only_fingerprint(&original)
            .unwrap_or_else(|error| unreachable!("summary serializes: {error}"));
        let mut changed = original;
        changed.protected.first_receive_address.push('x');
        let changed_fingerprint = watch_only_fingerprint(&changed)
            .unwrap_or_else(|error| unreachable!("summary serializes: {error}"));
        assert_ne!(original_fingerprint, changed_fingerprint);
    }

    #[test]
    fn verification_accepts_uppercase_and_rejects_bad_or_mismatched_values() {
        let summary = summary();
        let fingerprint = watch_only_fingerprint(&summary)
            .unwrap_or_else(|error| unreachable!("summary serializes: {error}"));
        verify_watch_only_fingerprint(&fingerprint.to_ascii_uppercase(), &summary)
            .unwrap_or_else(|error| unreachable!("uppercase fingerprint matches: {error}"));

        assert!(matches!(
            verify_watch_only_fingerprint("not-a-fingerprint", &summary),
            Err(Error::InvalidWatchOnlyFingerprint)
        ));
        assert!(matches!(
            verify_watch_only_fingerprint(&"00".repeat(32), &summary),
            Err(Error::WatchOnlyFingerprintMismatch)
        ));
    }
}
