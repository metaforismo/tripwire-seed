# Threat model

## Overview

`tripwire-seed` is a local Rust CLI that creates or inspects a BIP39 mnemonic
and passphrase, derives public BIP84 metadata, fingerprints and verifies recovery
against a prior watch-only export, and optionally exports secrets. Its primary
runtime surfaces are the interactive terminal in `src/main.rs`, random-word and
dice generation in `src/passphrase.rs`, derivation in `src/wallet.rs`, and
file/SeedQR handling in `src/export.rs`.

The assets are the mnemonic, BIP39 passphrase, derived private key material,
correct association between the decoy and protected wallets, watch-only xpub
privacy, integrity of recovery references, and the authenticity of source code
and built binaries.

## Threat Model, Trust Boundaries, and Assumptions

Trust boundaries:

- Human operator ↔ terminal input/output.
- Operating-system CSPRNG ↔ generated entropy.
- Physical dice and transcription ↔ dice collector.
- Secret mnemonic/passphrase ↔ BIP39 and BIP32 dependency code.
- Process memory ↔ operating system, allocator, swap, crash dumps, and malware.
- Process ↔ filesystem for public references and public or plaintext exports.
- Watch-only JSON ↔ a separately retained fingerprint and its storage or
  communication channel.
- Source repository ↔ dependency registry, CI actions, compiler, and release
  artifacts.
- Public xpub/descriptor data ↔ external wallet applications and monitoring
  services.

Operator-controlled inputs include dice rolls, network, passphrase word count,
existing mnemonic/passphrase values, confirmation phrases, watch-only reference
paths, expected fingerprints, and output paths. Developer-controlled inputs
include source changes, dependencies, CI workflows, and test vectors.
Attacker-controlled inputs can include a malicious local path or filesystem
race, a crafted, oversized, or internally inconsistent watch-only reference, a
substituted fingerprint, poisoned dependency or build environment, terminal
capture, malware, a biased entropy source, deceptive wallet software, and
crafted passphrase text supplied during an inspection workflow.

Security invariants:

- Runtime wallet generation, derivation, fingerprinting, and recovery
  verification require no network.
- Secret values are not accepted as CLI arguments or written to logs by design.
- Watch-only output and its fingerprint contain no mnemonic, passphrase, seed,
  xprv, or private key.
- Secret display, SeedQR, and plaintext export are separate explicit actions.
- Output creation never overwrites an existing path.
- Watch-only and plaintext secret files are created owner-only on Unix before
  content is written; plaintext secret export on unsupported platforms fails
  closed.
- Random-source failure aborts generation.
- Construction entropy is claimed only for the implemented uniform generators.
- Dice selection is unbiased when rolls are independent and fair.
- Decoy/protected equality is checked using full BIP84 account xpubs.
- Exported receive and change descriptors include BIP380 checksums and refuse a
  second checksum suffix.
- Watch-only references are bounded, decoded with a strict version 1 schema,
  checked for semantic consistency, and compared exactly before a recovery
  drill is reported as successful.
- Semantic validation parses each account xpub, reconstructs its first receive
  address and both descriptors, checks fixed role/path policy, and recomputes
  the account-xpub equality result.
- A supplied watch-only fingerprint is validated and compared before any
  mnemonic or passphrase prompt is shown.

Assumptions:

- The operator uses a clean, trusted, offline machine and verified source or
  binary.
- Physical dice are fair and entered faithfully.
- The operator can protect the screen from cameras and observers.
- Destination wallets implement BIP39/BIP32/BIP84 consistently.
- A recovery reference was obtained through a trusted channel and protected
  against substitution when authenticity matters.
- When fingerprint verification is used, the expected fingerprint was stored or
  communicated independently from the JSON reference.
- Repository and dependency review happen before real-fund use.

Out of scope are protection against a compromised kernel, firmware, compiler,
CPU, RNG implementation, terminal, wallet application, physical coercion,
camera, invasive side channel, or an attacker who already has both secrets.
The tool does not monitor decoy funds, alert on spends, encrypt backups, provide
secure deletion, create digital signatures or MACs, certify third-party wallets,
or prove global uniqueness.

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
addresses, emits BIP380-checksummed descriptors, and tests official BIP84 and
BIP380 vectors. The recovery command derives on the network recorded in a prior
reference and exact-compares all version 1 public metadata. That catches wrong
secrets, a wrong network, or altered public fields, but it does not prove that an
external wallet uses the same policy. Wallet-specific account policies can
still differ; users must complete recovery drills.

### Watch-only reference integrity

Watch-only exports disclose address relationships. A substituted reference can
make a correct recovery appear to fail or can be paired with attacker-chosen
secrets to create a misleading success. References are decoded before secret
input, limited to 64 KiB, reject unknown fields, require the exact version 1
schema and account policy, and are compared in full.

The loader also rejects public fields that contradict one another. It parses
each account xpub, derives branch `0`, index `0`, reconstructs the receive and
change descriptors with BIP380 checksums, checks the fixed role and BIP84 path,
and recomputes the equality of the two account xpubs. This prevents a file from
being accepted merely because each field is individually well-formed.

The four-byte master fingerprint cannot be derived from an account xpub because
the account sits below a hardened path. The loader can validate only its
canonical representation and consistent use in the descriptors. It cannot prove
that an attacker-chosen fingerprint and otherwise self-consistent public data
originated from a claimed master key.

Likewise, testnet and signet public data share BIP44 coin type `1`, `tpub`
extended-key serialization, and `tb1` native-SegWit addresses. Semantic checks
cannot infer which of those two chains the operator intended. The serialized
network is policy metadata; an independent reference fingerprint is what makes
a later substitution of that field detectable.

The domain-separated SHA-256 fingerprint commits to compact serialization of
every supported public field. The CLI can compare it before requesting secrets.
This detects substitution only when the expected fingerprint came through an
independent authenticated channel. If an attacker can replace both the JSON and
the stored fingerprint, the comparison provides no authenticity. The
fingerprint is not a signature, MAC, secret, or proof of provenance.

### Exports and filesystem

Watch-only JSON contains no spending secret, but account xpubs, descriptors,
addresses, roles, and fingerprints reveal financial relationships. On Unix the
program therefore creates watch-only references with mode `0600` before writing
bytes, using the same no-overwrite creation primitive as secret export. This is
a privacy default, not a claim that watch-only data becomes secret key material.
Other platforms retain their native ACL behavior for watch-only metadata.

SeedQR exposes the mnemonic to any camera. Plaintext exports expose both wallets
and may persist in SSD flash, snapshots, or backups. Plaintext secret export
uses confirmation gates, `create_new`, Unix mode `0600`, synchronization, and
fail-closed platform behavior. Neither path can make later deletion reliable or
defend an attacker-controlled parent directory, a compromised filesystem, or a
privileged local observer.

### Build and supply chain

Malicious dependencies, CI actions, or compiler artifacts can steal secrets.
The repository commits `Cargo.lock`, forbids unsafe code locally, pins workflow
actions to commit SHAs, runs RustSec audit, cargo-deny, dependency review, and
CodeQL, and documents source builds.

The release-candidate workflow performs two clean native builds per target on
the same GitHub-hosted runner, requires byte-identical executables, runs the
fixed public-vector self-test on both, creates deterministic ZIP packages and
SHA-256 sidecars, and submits main-branch archives for GitHub SLSA provenance
attestation. Pull-request builds retain read-only repository permissions and do
not receive an attestation-writing token.

These controls provide traceable same-runner evidence, not complete artifact
authenticity or independent reproducibility. A compromised runner, compiler,
linker, Python runtime, dependency, or GitHub attestation service can still
produce and attest malicious output. Equal builds within one environment can
repeat the same compromise. ZIP bytes can also vary across independent Python
or zlib implementations even when the executable is identical. The remaining
pre-release gate is reproduction on separately administered machines plus
external review; neither CI provenance nor checksums substitute for those
assurances.

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
- Recovery verification reporting success when the full supported public wallet
  policy does not match the supplied reference.
- Semantic validation accepting contradictory account xpub, descriptor, address,
  role, derivation, or collision metadata.
- Fingerprint verification reporting success for a different strict version 1
  watch-only reference.

### Medium

- Public xpub/descriptor disclosure beyond the selected output path.
- A denial of service from crafted interactive or watch-only input.
- Audit output making a materially misleading strength claim without direct key
  compromise.
- CI or documentation drift that weakens a defense but does not reach a secret
  at runtime by itself.

### Low

- Non-secret error-message quality, terminal formatting defects, or inaccurate
  non-security metadata.
- Failure to zeroize a clearly public buffer.
- Documentation issues that do not affect secret handling or recovery behavior.
