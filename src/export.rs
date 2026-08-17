//! Explicit export and verification functions with bounded, fail-closed defaults.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use bip39::Mnemonic;
use qrcode::{QrCode, render::unicode};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    wallet::{TripwireSummary, validate_tripwire_summary},
};

/// Maximum accepted size of a watch-only reference file.
pub const MAX_WATCH_ONLY_BYTES: usize = 64 * 1024;

/// Write semantically valid watch-only metadata as pretty JSON, refusing to
/// overwrite a path.
///
/// On Unix, the file is created with mode 0600 before any metadata is written.
/// This protects financial privacy by default even though watch-only metadata
/// contains no spending secret.
///
/// # Errors
///
/// Returns an error when the public fields are inconsistent, serialization
/// fails, the path already exists, or the file cannot be created, written, or
/// synchronized.
pub fn write_watch_only(path: &Path, summary: &TripwireSummary) -> Result<()> {
    validate_tripwire_summary(summary)?;
    let encoded = serde_json::to_vec_pretty(summary)?;
    let mut file = create_new_file(path, true)?;
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// Read and validate one bounded version 1 watch-only reference.
///
/// Unknown fields, unsupported schemas, account-policy changes, and internally
/// inconsistent public metadata fail closed. The file contains public wallet
/// metadata, but its size is still bounded to prevent an attacker-controlled
/// path from causing unbounded allocation.
///
/// # Errors
///
/// Returns an error when the file cannot be read, exceeds
/// [`MAX_WATCH_ONLY_BYTES`], is not strict JSON for the supported schema, uses
/// another account policy, or contains public fields that do not agree with its
/// account xpubs and collision metadata.
pub fn read_watch_only(path: &Path) -> Result<TripwireSummary> {
    let mut limited = File::open(path)?.take((MAX_WATCH_ONLY_BYTES + 1) as u64);
    let mut encoded = Vec::new();
    limited.read_to_end(&mut encoded)?;
    if encoded.len() > MAX_WATCH_ONLY_BYTES {
        return Err(Error::WatchOnlyTooLarge {
            max: MAX_WATCH_ONLY_BYTES,
        });
    }

    let summary: TripwireSummary = serde_json::from_slice(&encoded)?;
    validate_tripwire_summary(&summary)?;
    Ok(summary)
}

/// Require an exact match between a trusted reference and freshly derived data.
///
/// This compares the network, account policy, full account xpubs, descriptors,
/// first addresses, and collision metadata. It does not authenticate the
/// reference file or prove that an external wallet follows the same policy.
///
/// # Errors
///
/// Returns [`Error::WatchOnlyMismatch`] when any public field differs.
pub fn verify_watch_only(expected: &TripwireSummary, actual: &TripwireSummary) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::WatchOnlyMismatch)
    }
}

/// Build the standard numeric `SeedQR` payload (four zero-padded digits per word).
#[must_use]
pub fn seedqr_payload(mnemonic: &Mnemonic) -> Zeroizing<String> {
    let mut payload = String::with_capacity(mnemonic.word_count() * 4);
    for index in mnemonic.word_indices() {
        push_decimal_digit(&mut payload, index / 1_000);
        push_decimal_digit(&mut payload, (index / 100) % 10);
        push_decimal_digit(&mut payload, (index / 10) % 10);
        push_decimal_digit(&mut payload, index % 10);
    }
    Zeroizing::new(payload)
}

/// Render a numeric `SeedQR` payload for terminal display.
///
/// # Errors
///
/// Returns an error if the QR encoder cannot represent the payload.
pub fn render_seedqr(mnemonic: &Mnemonic) -> Result<Zeroizing<String>> {
    let payload = seedqr_payload(mnemonic);
    let code = QrCode::new(payload.as_bytes())?;
    Ok(Zeroizing::new(
        code.render::<unicode::Dense1x2>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .build(),
    ))
}

#[derive(Serialize)]
struct PlaintextSecretBundle<'a> {
    schema: &'static str,
    warning: &'static str,
    mnemonic: &'a str,
    bip39_passphrase: &'a str,
}

/// Write a plaintext secret bundle on Unix with mode 0600 and no overwrite.
///
/// This is intentionally not available on platforms where version 0.1 cannot
/// establish equivalent owner-only permissions before creating the file.
///
/// # Errors
///
/// Returns an error when serialization fails, the path already exists, secure
/// creation is unsupported, or the file cannot be created, written, or synced.
pub fn write_plaintext_secret_bundle(
    path: &Path,
    mnemonic: &Mnemonic,
    passphrase: &str,
) -> Result<()> {
    #[cfg(unix)]
    {
        let mnemonic_text = Zeroizing::new(mnemonic.to_string());
        let bundle = PlaintextSecretBundle {
            schema: "tripwire-seed/plaintext-secrets/v1",
            warning: "Anyone who reads this file can control both wallets. Move it only via trusted offline media.",
            mnemonic: mnemonic_text.as_str(),
            bip39_passphrase: passphrase,
        };
        let encoded = Zeroizing::new(serde_json::to_vec_pretty(&bundle)?);
        let mut file = create_new_file(path, true)?;
        file.write_all(encoded.as_slice())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (path, mnemonic, passphrase);
        Err(Error::SecretExportUnsupported)
    }
}

fn push_decimal_digit(output: &mut String, digit: usize) {
    debug_assert!(digit <= 9);
    output.push(char::from(b'0' + digit.to_le_bytes()[0]));
}

fn create_new_file(path: &Path, owner_only: bool) -> Result<std::fs::File> {
    if path.exists() {
        return Err(Error::OutputExists(path.to_path_buf()));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    #[cfg(not(unix))]
    let _ = owner_only;

    options.open(path).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bip39::Language;

    use super::*;
    use crate::wallet::{WalletNetwork, derive_tripwire_summary};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PASSPHRASE: &str = "correct protected value";

    fn summary() -> TripwireSummary {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        derive_tripwire_summary(&mnemonic, PASSPHRASE, WalletNetwork::Bitcoin)
            .unwrap_or_else(|error| unreachable!("valid derivation: {error}"))
    }

    #[test]
    fn seedqr_payload_is_fixed_width() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        let payload = seedqr_payload(&mnemonic);
        assert_eq!(payload.len(), 48);
        assert!(payload.ends_with("0003"));
    }

    #[test]
    fn seedqr_renders_for_official_vector() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        let rendered =
            render_seedqr(&mnemonic).unwrap_or_else(|error| unreachable!("QR renders: {error}"));
        assert!(rendered.contains('█'));
    }

    #[test]
    fn watch_only_export_contains_no_secret_fields() {
        let summary = summary();
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("watch-only.json");
        write_watch_only(&output, &summary)
            .unwrap_or_else(|error| unreachable!("write succeeds: {error}"));
        let contents = fs::read_to_string(output)
            .unwrap_or_else(|error| unreachable!("read succeeds: {error}"));
        assert!(!contents.contains(MNEMONIC));
        assert!(!contents.contains(PASSPHRASE));
        assert!(!contents.contains("xprv"));
        assert!(contents.contains("account_xpub"));
        for descriptor in [
            &summary.decoy.receive_descriptor,
            &summary.decoy.change_descriptor,
            &summary.protected.receive_descriptor,
            &summary.protected.change_descriptor,
        ] {
            let (body, checksum) = descriptor
                .rsplit_once('#')
                .unwrap_or_else(|| unreachable!("generated descriptor has a checksum"));
            assert_eq!(checksum.len(), 8);
            assert_eq!(
                crate::descriptor::descriptor_checksum(body)
                    .unwrap_or_else(|error| unreachable!("generated descriptor is valid: {error}")),
                checksum
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn watch_only_export_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("watch-only.json");
        write_watch_only(&output, &summary())
            .unwrap_or_else(|error| unreachable!("write succeeds: {error}"));
        let mode = fs::metadata(&output)
            .unwrap_or_else(|error| unreachable!("metadata succeeds: {error}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn watch_only_reference_round_trips_and_matches_exactly() {
        let expected = summary();
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("watch-only.json");
        write_watch_only(&output, &expected)
            .unwrap_or_else(|error| unreachable!("write succeeds: {error}"));

        let decoded = read_watch_only(&output)
            .unwrap_or_else(|error| unreachable!("strict reference decodes: {error}"));
        assert_eq!(decoded, expected);
        verify_watch_only(&expected, &decoded)
            .unwrap_or_else(|error| unreachable!("identical summaries match: {error}"));
    }

    #[test]
    fn recovery_verification_rejects_any_public_mismatch() {
        let expected = summary();
        let mut actual = expected.clone();
        actual.protected.first_receive_address.push('x');
        assert!(matches!(
            verify_watch_only(&expected, &actual),
            Err(Error::WatchOnlyMismatch)
        ));
    }

    #[test]
    fn watch_only_input_is_bounded_before_json_decoding() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("oversized.json");
        fs::write(&output, vec![b' '; MAX_WATCH_ONLY_BYTES + 1])
            .unwrap_or_else(|error| unreachable!("test fixture writes: {error}"));
        assert!(matches!(
            read_watch_only(&output),
            Err(Error::WatchOnlyTooLarge {
                max: MAX_WATCH_ONLY_BYTES
            })
        ));
    }

    #[test]
    fn unsupported_watch_only_schema_fails_closed() {
        let mut unsupported = summary();
        unsupported.schema = "tripwire-seed/watch-only/v2".to_owned();
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("unsupported.json");
        let encoded = serde_json::to_vec_pretty(&unsupported)
            .unwrap_or_else(|error| unreachable!("fixture serializes: {error}"));
        fs::write(&output, encoded)
            .unwrap_or_else(|error| unreachable!("test fixture writes: {error}"));
        assert!(matches!(
            read_watch_only(&output),
            Err(Error::UnsupportedWatchOnlyFormat)
        ));
    }

    #[test]
    fn internally_inconsistent_watch_only_reference_fails_closed() {
        let mut inconsistent = summary();
        inconsistent.decoy.first_receive_address.push('x');
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("inconsistent.json");
        let encoded = serde_json::to_vec_pretty(&inconsistent)
            .unwrap_or_else(|error| unreachable!("fixture serializes: {error}"));
        fs::write(&output, encoded)
            .unwrap_or_else(|error| unreachable!("test fixture writes: {error}"));
        assert!(matches!(
            read_watch_only(&output),
            Err(Error::InvalidWatchOnlyReference)
        ));
    }

    #[test]
    fn inconsistent_watch_only_export_is_not_created() {
        let mut inconsistent = summary();
        inconsistent.collision_check.same_account_xpub =
            !inconsistent.collision_check.same_account_xpub;
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("inconsistent.json");
        assert!(matches!(
            write_watch_only(&output, &inconsistent),
            Err(Error::InvalidWatchOnlyReference)
        ));
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn secret_export_is_owner_only_and_no_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("secrets.json");
        write_plaintext_secret_bundle(&output, &mnemonic, "protected")
            .unwrap_or_else(|error| unreachable!("write succeeds: {error}"));
        let mode = fs::metadata(&output)
            .unwrap_or_else(|error| unreachable!("metadata succeeds: {error}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(matches!(
            write_plaintext_secret_bundle(&output, &mnemonic, "protected"),
            Err(Error::OutputExists(_))
        ));
    }
}
