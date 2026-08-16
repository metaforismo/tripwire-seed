# Roadmap

## Before 0.1.0

- Independent review of entropy sampling and BIP39/BIP84 derivation.
- Reproduce builds on Linux, macOS, and Windows.
- Verify manual recovery with current Sparrow, COLDCARD, and Ashigaru releases
  using unfunded signet/testnet material, and exact-match each drill against a
  prior watch-only export with `tripwire-seed verify`.
- Review terminal behavior, memory lifetime, filesystem races, and Windows
  owner-only secret export options.
- Publish signed source tag and checksums only after the gates above pass.

## Later candidates

- Deterministic, independently testable entropy transcripts that reveal no
  secret material.
- Optional multi-decoy planning without persistent passphrase storage.
- Reproducible binary build documentation.
- Privacy-preserving decoy monitoring design, only if its metadata tradeoffs can
  be made explicit and safe.

Encrypted vault storage, telemetry, hosted web services, and automatic network
monitoring are intentionally not planned for version 0.1.
