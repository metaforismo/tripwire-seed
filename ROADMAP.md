# Roadmap

## Automated evidence already implemented

- Deterministic public-vector self-test runs on every native release candidate.
- Linux, macOS, and Windows candidates are built twice in clean target
  directories and require byte-identical executables on each GitHub-hosted
  runner.
- Main-branch candidate archives receive SHA-256 sidecars and GitHub SLSA
  provenance attestations.
- CI covers formatting, Clippy, Rust tests, rustdoc, MSRV, macOS and Windows,
  RustSec, cargo-deny, dependency review, and CodeQL.

These controls are evidence, not a stable-release decision. Same-runner equality
does not replace independent reproduction, the self-test does not authenticate a
binary, and CI does not replace external review or real recovery drills.

## Before 0.1.0

- [ ] Reproduce candidate executables on separately administered Linux, macOS,
  and Windows systems under
  [#7](https://github.com/metaforismo/tripwire-seed/issues/7). The current CI
  double builds and attestations are not independent cross-machine
  reproducibility.
- [ ] Complete version-pinned, unfunded recovery drills with Sparrow, COLDCARD,
  and Ashigaru under
  [#8](https://github.com/metaforismo/tripwire-seed/issues/8), following the
  [recovery drill protocol](docs/RECOVERY_DRILL.md). Exact-match each drill
  against a prior strict watch-only export and an independently retained
  fingerprint with `tripwire-seed verify`.
- [ ] Obtain an independent commit-pinned security review under
  [#9](https://github.com/metaforismo/tripwire-seed/issues/9), using the
  [first stable-release audit scope](docs/AUDIT_SCOPE.md). This review must
  explicitly cover entropy, derivation, terminal behavior, memory lifetime,
  filesystem races, exports, Windows fail-closed behavior, supply chain, and
  release claims.
- [ ] Remediate and independently recheck every Critical, High, or otherwise
  release-blocking finding.
- [ ] Re-run every automated and manual gate on the final frozen audited commit.
- [ ] Publish a signed source tag and checksums only after all gates above pass.

## Later candidates

- Deterministic, independently testable entropy transcripts that reveal no
  secret material.
- Optional multi-decoy planning without persistent passphrase storage.
- Privacy-preserving decoy monitoring design, only if its metadata tradeoffs can
  be made explicit and safe.

Encrypted vault storage, telemetry, hosted web services, and automatic network
monitoring are intentionally not planned for version 0.1.
