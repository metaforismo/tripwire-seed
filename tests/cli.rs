//! Black-box checks for the public CLI safety boundary.

use std::process::Command;

use bip39::{Language, Mnemonic};
use tripwire_seed::{
    export::write_watch_only,
    fingerprint::watch_only_fingerprint,
    self_test::SELF_TEST_SCHEMA,
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
    assert!(stdout.contains("self-test"));
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

#[test]
fn self_test_is_non_interactive_machine_readable_and_secret_free() {
    let output = binary()
        .args(["self-test", "--json"])
        .output()
        .unwrap_or_else(|error| unreachable!("binary runs: {error}"));
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| unreachable!("self-test emits JSON: {error}"));
    assert_eq!(report["schema"], SELF_TEST_SCHEMA);
    assert_eq!(report["public_vectors_only"], true);
    assert_eq!(report["passed"], true);
    assert_eq!(report["checks"].as_array().map_or(0, std::vec::Vec::len), 9);

    let stdout = String::from_utf8_lossy(&output.stdout);
    for excluded in [
        "abandon abandon",
        "TREZOR",
        "c55257c360c07c72",
        "xpub6CatWdiZiodmU",
        "wpkh([73c5da0a",
        "bc1qcr8te4kr609g",
    ] {
        assert!(!stdout.contains(excluded));
    }
}
