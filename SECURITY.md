# Security policy

## Supported versions

Until the first stable release, only the latest commit on `main` is supported.
The project is experimental and has not received an independent audit.

## Report a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not open a
public issue for an undisclosed vulnerability and never include a real mnemonic,
passphrase, xprv, wallet backup, or funded address in a report. Use synthetic
test vectors only.

Include the affected commit, platform, exact command shape with secrets removed,
impact, reproduction steps, and any proposed mitigation. If private reporting
is unavailable, open a public issue containing no vulnerability details and ask
the maintainer to establish a private channel.

There is no bug bounty or guaranteed response time. The maintainer will aim to
acknowledge complete reports within seven days and coordinate disclosure after a
fix and release path exist.

## Highest-priority classes

- Secret disclosure through logs, errors, process arguments, watch-only files,
  CI artifacts, or unexpected filesystem writes.
- Predictable or biased generated entropy.
- Incorrect BIP39/BIP32/BIP84 derivation or misleading recovery metadata.
- Plaintext export that bypasses confirmation, permissions, or no-overwrite
  behavior.
- Supply-chain changes that can execute while secrets are handled.

The repository-wide assumptions, boundaries, and severity calibration are in
[the threat model](docs/THREAT_MODEL.md).

## Safe research

Use only official public test vectors and unfunded, disposable material. Do not
scan third-party wallets, access funds, publish live secrets, or test against
another person's device or account without explicit authorization.
