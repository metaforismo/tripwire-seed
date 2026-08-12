# Changelog

All notable changes will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Offline interactive CLI for creating and inspecting a BIP39 decoy/protected
  wallet pair.
- CSPRNG and unbiased physical-dice passphrase generation.
- Conservative passphrase audit and exact account-xpub comparison.
- Watch-only JSON, opt-in SeedQR, and gated Unix plaintext export.
- BIP380 checksums on receive and change descriptors in terminal and watch-only
  JSON output.
- BIP84 vectors, redaction, permissions, no-overwrite, and TTY boundary tests.
- Security policy, threat model, cryptographic design, CI, dependency review,
  RustSec audit, cargo-deny, CodeQL, and Dependabot configuration.
