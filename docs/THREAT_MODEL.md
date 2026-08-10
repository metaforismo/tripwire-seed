# Threat model

## Overview

`tripwire-seed` is a local Rust CLI that creates or inspects a BIP39 mnemonic
and passphrase, derives public BIP84 metadata, and optionally exports secrets.
Its primary runtime surfaces are the interactive terminal in `src/main.rs`,
random-word and dice generation in `src/passphrase.rs`, derivation in
`src/wallet.rs`, and file/SeedQR export in `src/export.rs`.

The assets are the mnemonic, BIP39 passphrase, derived private key material,
correct association between the decoy and protected wallets, watch-only xpub
privacy, and the authenticity of source code and built binaries.

## Threat Model, Trust Boundaries, and Assumptions

Trust boundaries:

- Human operator ↔ terminal input/output.
- Operating-system CSPRNG ↔ generated entropy.
- Physical dice and transcription ↔ dice collector.
- Secret mnemonic/passphrase ↔ BIP39 and BIP32 dependency code.
- Process memory ↔ operating system, allocator, swap, crash dumps, and malware.
- Process ↔ filesystem for public and plaintext exports.
- Source repository ↔ dependency registry, CI actions, compiler, and release
  artifacts.
- Public xpub/descriptor data ↔ external wallet applications and monitoring
  services.

Operator-controlled inputs include dice rolls, network, passphrase word count,
existing mnemonic/passphrase values, confirmation phrases, and output paths.
Developer-controlled inputs include source changes, dependencies, CI workflows,
and test vectors. Attacker-controlled inputs can include a malicious local path
or filesystem race, poisoned dependency or build environment, terminal capture,
malware, a biased entropy source, deceptive wallet software, and crafted
passphrase text supplied during an inspection workflow.

Security invariants:

- Runtime wallet generation and derivation require no network.
- Secret values are not accepted as CLI arguments or written to logs by design.
- Watch-only output contains no mnemonic, passphrase, seed, xprv, or private key.
- Secret display, SeedQR, and plaintext export are separate explicit actions.
- Output creation never overwrites an existing path.
- Plaintext secret files are created owner-only on Unix before content is
  written; unsupported platforms fail closed.
- Random-source failure aborts generation.
- Construction entropy is claimed only for the implemented uniform generators.
- Dice selection is unbiased when rolls are independent and fair.
- Decoy/protected equality is checked using full BIP84 account xpubs.

Assumptions:

- The operator uses a clean, trusted, offline machine and verified source or
  binary.
- Physical dice are fair and entered faithfully.
- The operator can protect the screen from cameras and observers.
- Destination wallets implement BIP39/BIP32/BIP84 consistently.
- Repository and dependency review happen before real-fund use.

Out of scope are protection against a compromised kernel, firmware, compiler,
CPU, RNG implementation, terminal, wallet application, physical coercion,
camera, invasive side channel, or an attacker who already has both secrets.
The tool does not monitor decoy funds, alert on spends, encrypt backups, provide
secure deletion, or prove global uniqueness.

## Attack Surface, Mitigations, and Attacker Stories

### Terminal and process memory

An attacker with malware or terminal recording can capture all secrets. The CLI
requires a TTY, uses no-echo prompts for secret input, avoids secret command-line
arguments, redacts secret-bearing `Debug` output, and zeroizes supported owned
buffers. These controls reduce accidental disclosure but do not defeat a
compromised host or screen capture.

### Entropy generation

A failed CSPRNG aborts. System word selection is unbiased. Dice input rejects
invalid characters and uses a mathematically complete rejection range. A loaded
die, selective rerolling, or fabricated sequence remains undetectable.

### Human passphrases

An attacker who obtains the mnemonic can test passphrase candidates offline.
The audit therefore refuses to estimate entropy for human choice and flags
short, repeated, numeric-only, empty, and seed-shaped inputs. The default
generator targets 132 bits. No finite checklist can prove a human phrase is
unknown to an attacker.

### Derivation and interoperability

A typo creates another valid wallet and can cause permanent loss. The CLI
requires backup re-entry after generation, emits fingerprints and first
addresses, and tests the official BIP84 vector. Wallet-specific account policies
can still differ; users must complete recovery drills.

### Exports and filesystem

Watch-only exports disclose address relationships. SeedQR exposes the mnemonic
to any camera. Plaintext exports expose both wallets and may persist in SSD
flash, snapshots, or backups. The program uses confirmation gates, `create_new`,
Unix mode `0600`, synchronization, and fail-closed platform behavior. It cannot
make later deletion reliable or defend an attacker-controlled parent directory.

### Build and supply chain

Malicious dependencies, CI actions, or compiler artifacts can steal secrets.
The repository commits `Cargo.lock`, forbids unsafe code locally, pins workflow
actions to commit SHAs, runs RustSec audit, cargo-deny, dependency review, and
CodeQL, and documents source builds. These controls do not make the supply chain
perfect or substitute for reproducible independent builds and external audit.

## Severity Calibration (Critical, High, Medium, Low)

### Critical

- Any reachable path that sends, logs, persists, or includes mnemonic,
  passphrase, seed, xprv, or private keys without the explicit secret-export
  contract.
- Biased or predictable default entropy that materially reduces the claimed
  128-bit target.
- A derivation error that displays expected public metadata while generating a
  different spendable wallet.

### High

- Watch-only export accidentally containing secret material.
- Plaintext export creating broadly readable files or silently overwriting a
  backup.
- SeedQR or secret display occurring without the explicit confirmation gate.
- A passphrase normalization or network/path mismatch that can cause users to
  fund an unrecoverable wallet under documented steps.

### Medium

- Public xpub/descriptor disclosure beyond the selected output path.
- A denial of service from crafted interactive input.
- Audit output making a materially misleading strength claim without direct key
  compromise.
- CI or documentation drift that weakens a defense but does not reach a secret
  at runtime by itself.

### Low

- Non-secret error-message quality, terminal formatting defects, or inaccurate
  non-security metadata.
- Failure to zeroize a clearly public buffer.
- Documentation issues that do not affect secret handling or recovery behavior.
