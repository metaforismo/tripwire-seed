# Tripwire Seed

[![CI](https://github.com/metaforismo/tripwire-seed/actions/workflows/ci.yml/badge.svg)](https://github.com/metaforismo/tripwire-seed/actions/workflows/ci.yml)
[![CodeQL](https://github.com/metaforismo/tripwire-seed/actions/workflows/codeql.yml/badge.svg)](https://github.com/metaforismo/tripwire-seed/actions/workflows/codeql.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)

`tripwire-seed` is an offline-first Rust CLI for planning a BIP39 decoy
wallet and a passphrase-protected wallet from the same 12-word mnemonic.

> [!CAUTION]
> This is experimental security software and has not received an independent
> audit. Do not trust it with meaningful funds until you have reviewed the
> source, reproduced the tests, verified the build, and completed recovery
> drills on more than one compatible wallet.

The project is independent and is not affiliated with, endorsed by, or
sponsored by Ashigaru, Sparrow Wallet, COLDCARD, or their maintainers.

## What it does

- Generates a standard 128-bit BIP39 mnemonic using the operating-system CSPRNG.
- Generates a separate random-word BIP39 passphrase from either the CSPRNG or
  physical d6 rolls.
- Uses 12 independently selected passphrase words by default: 132 bits of
  construction entropy.
- Derives BIP84 account metadata for the base/decoy wallet (empty passphrase)
  and the protected wallet (non-empty passphrase).
- Compares the complete account xpubs locally; it does not call a server or
  pretend to perform a global collision search.
- Exports watch-only JSON by default, SeedQR only after confirmation, and
  plaintext secrets only behind a separate dangerous option.
- Audits human-entered passphrases conservatively without inventing an entropy
  number.

The name “tripwire” describes the decoy-funds design. The program does not
monitor the blockchain, send notifications, or detect a spend automatically.

## The wallet model

| Role | Mnemonic | BIP39 passphrase | Intended use |
| --- | --- | --- | --- |
| Decoy | same 12 words | empty | Small, plausible balance |
| Protected | same 12 words | high-entropy value | Primary wallet |

Every BIP39 passphrase produces a valid wallet. A typo does not produce an
error; it silently opens a different wallet. That is why the CLI displays
fingerprints and first receive addresses and requires backup re-entry after
generation.

This tool intentionally does **not** turn a human sentence into a mnemonic.
BIP39 describes transport for computer-generated randomness, not brainwallets.
It also does not claim that 11 chosen BIP39 words have one unique 12th word:
for a fixed 11-word prefix there are 128 valid checksum completions.

## Entropy choices

Each generated passphrase word is sampled uniformly from 2,048 English BIP39
words and contributes exactly 11 bits. The number is valid only for random
selection by the tool or its documented dice method.

| Words | Construction entropy | Guidance |
| ---: | ---: | --- |
| 6 | 66 bits | Below the project target; buys time only |
| 8 | 88 bits | Below the project target |
| 10 | 110 bits | Below the project target |
| 12 | 132 bits | Default; meets the 128-bit target |

Human choice, quotations, dates, personal facts, and modified song lyrics do
not inherit this table. BIP39 uses PBKDF2-HMAC-SHA512 with only 2,048 rounds, so
an attacker who obtains the mnemonic can test weak passphrase guesses offline.

## Build from source

Install Rust with `rustup`, review the checkout, and build with the committed
lockfile:

```console
git clone https://github.com/metaforismo/tripwire-seed.git
cd tripwire-seed
cargo build --release --locked
```

The runtime has no networking feature. Dependencies are required only to build
the program. For an air-gapped workflow, fetch and vendor dependencies on a
separate trusted machine, verify the transfer, then build offline.

## Use

Run the interactive wizard on a trusted offline computer:

```console
cargo run --release --locked -- create
```

Use physical dice for the passphrase:

```console
cargo run --release --locked -- create --passphrase-source dice
```

Inspect an existing pair without displaying its secrets:

```console
cargo run --release --locked -- inspect
```

Audit a passphrase without deriving wallet data:

```console
cargo run --release --locked -- audit-passphrase
```

Secret-taking commands require an interactive terminal. Mnemonics and
passphrases are read with terminal echo disabled and are never accepted as
command-line arguments, where shell history and process listings could expose
them.

## Exports

```console
# Public metadata: fingerprint, account xpub, descriptors, first addresses
tripwire-seed create --watch-only-out wallet.tripwire-watch-only.json

# Machine-readable mnemonic on screen; requires a separate confirmation
tripwire-seed create --show-seedqr

# DANGEROUS: owner-only plaintext JSON on Unix; requires a separate confirmation
tripwire-seed create --dangerous-secret-out backup.tripwire-secrets.json
```

Files are created with no-overwrite semantics. Plaintext secret export is
disabled on platforms where version 0.1 cannot establish owner-only permissions
before creation. Secure deletion is not promised: SSDs, snapshots, backups, and
copy-on-write filesystems can retain old data.

See [wallet import guidance](docs/WALLET_IMPORTS.md) before moving funds.

## Verification

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
```

The test suite includes the official BIP84 first-address vector, dice rejection
sampling, SeedQR encoding, redaction, no-overwrite behavior, Unix `0600` secret
permissions, and the non-interactive CLI boundary.

Read the [cryptographic design](docs/CRYPTOGRAPHIC_DESIGN.md),
[threat model](docs/THREAT_MODEL.md), [security policy](SECURITY.md), and
[roadmap](ROADMAP.md) before evaluating the project.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
