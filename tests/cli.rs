//! Black-box checks for the public CLI safety boundary.

use std::process::Command;

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
