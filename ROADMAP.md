# Roadmap

## Before 0.1.0

- Independent review of entropy sampling and BIP39/BIP84 derivation.
- Reproduce candidate executables on separately administered Linux, macOS, and
  Windows systems. CI now requires two byte-identical clean builds on each
  native GitHub-hosted runner and attests main-branch candidate archives, but
  that is not independent cross-machine reproducibility.
- Run the deterministic public-vector self-test on every release candidate; this
  checks packaged implementation behavior but does not authenticate an artifact
  or replace reproducibility and independent review.
- Verify manual recovery with current Sparrow, COLDCARD, and Ashigaru releases
  using unfunded signet/testnet material; exact-match each drill against a prior
  watch-only export and an independently retained fingerprint with
  `tripwire-seed verify`.
- Review terminal behavior, memory lifetime, filesystem races, and Windows
  owner-only secret export options.
- Publish signed source tag and checksums only after the gates above pass.

## Later candidates

- Deterministic, independently testable entropy transcripts that reveal no
  secret material.
- Optional multi-decoy planning without persistent passphrase storage.
- Privacy-preserving decoy monitoring design, only if its metadata tradeoffs can
  be made explicit and safe.

Encrypted vault storage, telemetry, hosted web services, and automatic network
monitoring are intentionally not planned for version 0.1.
