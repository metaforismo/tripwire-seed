//! Black-box checks for the public CLI safety boundary.

use std::process::Command;

use bip39::{Language, Mnemonic};
use tripwire_seed::{
    export::write_watch_only,
    fingerprint::watch_only_fingerprint,
    wallet::{WalletNetwork, derive_tripwire_summary},
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tripwire-seed"))
}

#[test]
fn help_is_available_without_a_terminal() {
    let output = binary()
        .arg("--help")
        .output()
        .unwrap_or_else(|error| unreachable!("binary runs: {error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Offline BIP39 tripwire wallet planner"));
    assert!(stdout.contains("create"));
    assert!(stdout.contains("inspect"));
    assert!(stdout.contains("fingerprint"));
    assert!(stdout.contains("verify"));
}

#[test]
fn secret_commands_reject_non_interactive_input() {
    for command in ["create", "inspect", "verify", "audit-passphrase"] {
        let mut process = binary();
        process.arg(command);
        if command == "verify" {
            process.args(["--watch-only", "reference.json"]);
        }
        let output = process
            .output()
            .unwrap_or_else(|error| unreachable!("binary runs: {error}"));
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("requires an interactive terminal"));
    }
}

#[test]
fn fingerprint_command_is_non_interactive_and_bounded_by_file_loader() {
    let output = binary()
        .args(["fingerprint", "--watch-only", "missing-reference.json"])
        .output()
        .unwrap_or_else(|error| unreachable!("binary runs: {error}"));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("I/O error"));
    assert!(!stderr.contains("requires an interactive terminal"));
}

#[test]
fn fingerprint_command_matches_the_library_without_a_terminal() {
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC)
        .unwrap_or_else(|error| unreachable!("official vector: {error}"));
    let summary = derive_tripwire_summary(&mnemonic, "protected", WalletNetwork::Signet)
        .unwrap_or_else(|error| unreachable!("valid derivation: {error}"));
    let expected = watch_only_fingerprint(&summary)
        .unwrap_or_else(|error| unreachable!("summary serializes: {error}"));
    let directory =
        tempfile::tempdir().unwrap_or_else(|error| unreachable!("temporary directory: {error}"));
    let reference = directory.path().join("watch-only.json");
    write_watch_only(&reference, &summary)
        .unwrap_or_else(|error| unreachable!("reference writes: {error}"));

    let output = binary()
        .arg("fingerprint")
        .arg("--watch-only")
        .arg(reference)
        .output()
        .unwrap_or_else(|error| unreachable!("binary runs: {error}"));
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), expected);
    assert!(output.stderr.is_empty());
}
