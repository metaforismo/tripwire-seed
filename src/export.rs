//! Explicit export functions with no-overwrite defaults.

use std::{fs::OpenOptions, io::Write, path::Path};

use bip39::Mnemonic;
use qrcode::{QrCode, render::unicode};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{Error, Result, wallet::TripwireSummary};

/// Write watch-only metadata as pretty JSON, refusing to overwrite a path.
///
/// # Errors
///
/// Returns an error when serialization fails, the path already exists, or the
/// file cannot be created, written, or synchronized.
pub fn write_watch_only(path: &Path, summary: &TripwireSummary) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(summary)?;
    let mut file = create_new_file(path, false)?;
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
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

fn create_new_file(path: &Path, secret: bool) -> Result<std::fs::File> {
    if path.exists() {
        return Err(Error::OutputExists(path.to_path_buf()));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    #[cfg(not(unix))]
    let _ = secret;

    options.open(path).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bip39::Language;

    use super::*;
    use crate::wallet::{WalletNetwork, derive_tripwire_summary};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC)
            .unwrap_or_else(|error| unreachable!("official vector: {error}"));
        let summary =
            derive_tripwire_summary(&mnemonic, "correct protected value", WalletNetwork::Bitcoin)
                .unwrap_or_else(|error| unreachable!("valid derivation: {error}"));
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
        let output = directory.path().join("watch-only.json");
        write_watch_only(&output, &summary)
            .unwrap_or_else(|error| unreachable!("write succeeds: {error}"));
        let contents = fs::read_to_string(output)
            .unwrap_or_else(|error| unreachable!("read succeeds: {error}"));
        assert!(!contents.contains(MNEMONIC));
        assert!(!contents.contains("correct protected value"));
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
