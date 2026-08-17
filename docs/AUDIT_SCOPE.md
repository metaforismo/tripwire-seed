# First stable-release audit scope

This document defines the normative scope for the independent assessment
required before the first stable release of Tripwire Seed. It does not claim
that an assessment has occurred, and it does not convert automated checks into
an independent audit.

## Freeze the target

An assessment must identify one immutable Git commit rather than `main` or
another moving branch. The reviewer and maintainer must record:

- the full 40-character commit SHA and repository URL;
- the release-candidate archive names and SHA-256 values, when binaries are in
  scope;
- the corresponding GitHub provenance attestation URLs or identifiers;
- the exact Rust, Cargo, LLVM/linker, operating-system, Python, and relevant
  security-tool versions used to reproduce evidence; and
- whether each candidate executable was independently reproduced under issue
  [#7](https://github.com/metaforismo/tripwire-seed/issues/7).

Any source, workflow, dependency, lockfile, or documentation change after the
freeze creates a new audit target. A release-blocking finding is closed only
against an explicit remediation commit and an independent recheck.

## In-scope implementation

The assessment covers the complete repository at the frozen commit, with
particular attention to:

- `src/passphrase.rs`: operating-system randomness, uniform word selection,
  physical-dice collection, rejection sampling, input bounds, normalization,
  and owned secret-buffer lifetime;
- `src/wallet.rs`: BIP39 seed construction, BIP32/BIP84 derivation, network and
  path policy, account metadata, decoy/protected separation, and exact recovery
  comparison;
- `src/descriptor.rs`: BIP380 descriptor construction, checksum generation,
  existing-checksum rejection, branch policy, and canonical output;
- `src/fingerprint.rs`: domain separation, canonical serialization, complete
  field coverage, parsing, comparison, and documented authenticity boundary;
- `src/export.rs`: watch-only schema, SeedQR rendering, dangerous plaintext
  export, no-overwrite behavior, Unix owner-only creation, synchronization,
  path handling, serialization, and zeroization boundaries;
- `src/audit.rs`: conservative passphrase warnings and the absence of invented
  entropy claims for human-chosen text;
- `src/self_test.rs`: fixed public vectors, report contents, deterministic
  behavior, and the limits of what a packaged self-test can establish;
- `src/main.rs`, `src/error.rs`, and `tests/cli.rs`: TTY enforcement, no-echo
  input, confirmation gates, CLI and environment boundaries, diagnostics,
  redaction, exit behavior, and non-interactive failure modes;
- every unit and CLI test as evidence for the property it explicitly exercises;
- `Cargo.toml`, `Cargo.lock`, `deny.toml`, the pinned Rust toolchain, and every
  GitHub Actions workflow and third-party Action SHA;
- release-candidate double builds, public metadata, deterministic ZIP creation,
  checksum sidecars, artifact permissions, and provenance generation; and
- README, cryptographic design, threat model, wallet-import guidance, recovery
  drill protocol, reproducible-build guidance, security policy, and roadmap for
  accurate and non-overstated claims.

Tests and documentation are themselves in scope. Their presence is not accepted
as proof without inspection and reproduction.

## Security properties to assess

The reviewer should attempt to falsify at least these properties:

1. Default mnemonic generation obtains 128 bits from the operating-system CSPRNG
   and aborts rather than substituting weak entropy after randomness failure.
2. Generated passphrase words are selected uniformly, and documented
   construction-entropy numbers apply only to implemented random generation.
3. Physical-dice collection introduces no modulo bias when rolls are independent
   and fair, and invalid or incomplete input fails safely.
4. Mnemonics and BIP39 passphrases are never accepted through ordinary command
   arguments, shell history, or non-interactive stdin.
5. BIP39 normalization and BIP32/BIP84 derivation produce the documented decoy
   and protected account metadata for every supported network and path.
6. A passphrase typo cannot be misreported as successful recovery of the
   intended protected wallet.
7. Watch-only output, fingerprints, logs, errors, tests, examples, CI output, and
   release artifacts contain no mnemonic, BIP39 passphrase, seed, xprv, or
   private key.
8. SeedQR display and dangerous plaintext export occur only after their explicit
   confirmation contracts and never as an accidental side effect.
9. Output creation never overwrites an existing path, and plaintext secret
   export never silently creates a broadly readable file.
10. Unsupported platforms fail closed when owner-only plaintext creation cannot
    be established before secret content is written.
11. A watch-only reference is size bounded, strict about unknown fields and
    schema version, and rejected when public fields contradict each other.
12. Semantic validation reconstructs expected addresses and BIP380-checksummed
    descriptors from each account xpub rather than trusting redundant fields.
13. Recovery verification cannot report success unless every supported public
    field matches the supplied reference exactly.
14. A supplied expected fingerprint is validated and compared before secret
    prompts, and documentation does not describe the fingerprint as a signature,
    MAC, password, or proof of origin.
15. Secret-bearing owned buffers are zeroized where the implementation claims,
    without implying protection from swap, copies outside ownership, crash
    dumps, a compromised host, or screen capture.
16. The runtime performs no network access and no hidden telemetry, monitoring,
    update check, or remote collision search.
17. Dependency, workflow, build, packaging, checksum, and provenance controls do
    not execute with unnecessary permissions or make stronger authenticity
    claims than their evidence supports.

## Required evidence on the frozen commit

Before reviewer sign-off, rerun and retain privacy-safe results for:

```console
python3 scripts/test_reproducible_release.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo run --locked -- self-test --json
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
```

Also require the repository's current:

- minimum-supported-Rust check;
- Linux, macOS, and Windows test matrix;
- RustSec and cargo-deny policy checks;
- pull-request dependency review;
- CodeQL analysis;
- native Linux, macOS, and Windows release-candidate double builds;
- candidate checksum verification and main-branch provenance attestations;
- independent cross-machine reproduction tracked in
  [#7](https://github.com/metaforismo/tripwire-seed/issues/7); and
- version-pinned, unfunded recovery drills tracked in
  [#8](https://github.com/metaforismo/tripwire-seed/issues/8).

Evidence must not contain a mnemonic, passphrase, seed, xprv, complete account
xpub, descriptor, address, SeedQR, wallet file, device identifier, production
path, or other wallet-derived material. Use official public vectors or newly
generated disposable, unfunded signet/testnet material only.

## Filesystem and platform review

The assessment must explicitly cover:

- creation-time permissions rather than permission repair after writing;
- symlink, existing-file, parent-directory, and path race behavior;
- partial writes, serialization failure, flush/synchronization behavior, and
  process interruption;
- Unix mode assumptions and the version 0.1 Windows fail-closed boundary;
- terminal echo restoration after errors or interruption;
- allocator, copy, formatting, QR-rendering, and error-conversion lifetimes for
  secret-bearing values; and
- the documented inability to guarantee secure deletion on SSDs, snapshots,
  backups, journaling, or copy-on-write filesystems.

## Explicit exclusions and accepted boundaries

The assessment does not certify:

- a compromised kernel, firmware, CPU, compiler, RNG implementation, terminal,
  camera environment, external wallet, hardware wallet, or build service;
- physical coercion, invasive side channels, or an attacker who already has both
  the mnemonic and BIP39 passphrase;
- that independently fair physical dice were actually used fairly;
- that a human-chosen phrase has measurable entropy or is absent from an
  attacker's private dictionary;
- global wallet uniqueness or a network-wide collision search;
- reliable secure deletion;
- third-party wallet security or compatibility outside the exact pinned recovery
  combinations tested under issue #8; or
- automatic monitoring of decoy funds, telemetry, hosted services, or network
  notifications, which are outside version 0.1.

An exclusion does not excuse a violation of this project's own invariants or a
misleading claim about checksums, fingerprints, zeroization, recovery,
reproducibility, or provenance.

## Reviewer deliverables

The independent reviewer should provide:

- identity or organization and relevant Bitcoin wallet, cryptography, Rust, and
  operating-system security experience;
- frozen commit and candidate artifact identifiers;
- methodology, tooling, environment, and limitations;
- findings with realistic prerequisites, impact, severity, and minimal safe
  reproduction using public or disposable unfunded material;
- confirmation of which security properties were actively tested;
- a list of unreviewed areas and inconclusive results;
- recheck status for every release-blocking remediation; and
- a non-sensitive conclusion suitable for publication.

Potentially harmful details must use GitHub private vulnerability reporting as
described in `SECURITY.md`. Public summaries should follow coordinated
remediation and must never include wallet secrets or funded-wallet metadata.

## Stable-release decision

Issue [#9](https://github.com/metaforismo/tripwire-seed/issues/9) remains open
until:

- all Critical, High, and release-blocking findings are remediated and
  independently rechecked;
- the frozen final commit passes every required automated and manual gate;
- independent reproduction under issue #7 is complete for all claimed targets;
- version-pinned recovery drills under issue #8 are complete for every claimed
  wallet/platform combination;
- supported and unsupported platforms and export modes are explicit; and
- a signed source tag and checksums are created only after those conditions hold.
