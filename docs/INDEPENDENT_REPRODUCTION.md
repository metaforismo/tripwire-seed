# Independent release-candidate reproduction

This document describes how an external operator can reproduce a Tripwire Seed
candidate and compare the resulting executable with the corresponding
main-branch GitHub Actions candidate.

It is a procedure and verification aid. Its presence in the repository does
**not** establish that an independent reproduction has occurred.

## Keep three questions separate

A useful reproduction record must distinguish:

1. **Reference integrity.** Did the operator obtain the intended GitHub artifact?
   Verify its separately obtained outer SHA-256, embedded sidecar, and
   main-branch provenance attestation.
2. **Executable equality.** Did the independently built executable match the
   reference executable? `scripts/verify_independent_reproduction.py` performs
   this comparison after validating both packages.
3. **Actual independence.** Was the build system separately administered, was
   the source obtained and reviewed independently, and did another reviewer
   inspect the evidence? Repository code cannot prove those facts.

A green verifier report answers the second question and supplies evidence for
the first. It does not answer the third by itself.

## Verifier safety boundary

The verifier treats every ZIP, sidecar, and metadata document as untrusted data.
By default it:

- opens size-bounded regular files without following a final symlink where the
  platform supports that control;
- rejects encrypted, duplicate, non-regular, absolute, drive-qualified,
  traversing, ambiguous, oversized, or unexpected ZIP members;
- requires the exact candidate member set, normalized timestamp, and fixed file
  permissions;
- rejects duplicate or unexpected JSON metadata fields;
- requires the frozen commit, target, package identity, source timestamp,
  linker mode, and self-test declarations to agree;
- verifies the outer artifact digest and both candidate sidecars;
- compares every packaged public document and the complete executable bytes; and
- keeps the reference executable in memory and never executes it.

Inspection-only mode is the default.

`--execute-reproduced-self-test` writes and executes only the reproduced
executable in a private temporary directory. This is an explicit trust decision:
the helper is not a sandbox and the process runs with the current user's
privileges. Use the flag only after reviewing the frozen source and the local
build. The reference executable is never run.

## Freeze the target

Before building, record:

```text
Repository: https://github.com/metaforismo/tripwire-seed
Frozen 40-character commit:
Native target:
Reference workflow run:
Reference artifact ID and name:
Reference outer artifact SHA-256:
Reference attestation identifier or URL:
Date:
Operator identity or pseudonym:
Independent reviewer identity or pseudonym:
```

Use exactly one supported native target:

```text
x86_64-unknown-linux-gnu
aarch64-apple-darwin
x86_64-pc-windows-msvc
```

Do not use `main` or another moving branch as the review target.

## Obtain the reference artifact

Download the target artifact from the successful main-branch `Release candidate`
workflow for the frozen commit. Record the outer artifact digest returned by
GitHub through a separate channel from the downloaded bytes.

Verify the main-branch candidate attestation separately, for example:

```console
gh attestation verify \
  tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip \
  --repo metaforismo/tripwire-seed
```

The verifier intentionally does not implement a second GitHub attestation
client. The expected outer SHA-256 is supplied explicitly, while GitHub's
supported tooling remains responsible for provenance verification.

Artifact integrity and provenance still do not prove that GitHub, the compiler,
dependencies, or the runner image were uncompromised.

## Prepare the independent build system

A qualifying reproduction should use a system administered separately from the
original GitHub-hosted runner and from the maintainer who produced the reference.
Record at least:

```text
Operating-system name and version:
Architecture:
Rust and rustup versions:
rustc --version --verbose:
cargo --version --verbose:
LLVM or native linker version:
Python version:
Git version:
Dependency source/cache preparation:
Source acquisition and verification method:
Relevant build environment variables:
```

Review the checkout and confirm:

```console
git rev-parse HEAD
git status --short
```

The first command must print the frozen commit. The second must be empty before
the build.

For an air-gapped build, obtain and verify the source snapshot, Rust toolchain,
and vendored or cached dependencies through a documented transfer procedure.
Do not replace the committed lockfile or normalize a mismatching binary after
the fact.

## Produce the local candidate

From the reviewed frozen checkout, run:

```console
python3 scripts/test_reproducible_release.py
python3 scripts/reproducible_release.py \
  --target x86_64-unknown-linux-gnu \
  --output-dir dist
```

Use `aarch64-apple-darwin` on Apple Silicon or
`x86_64-pc-windows-msvc` on 64-bit Windows. The output is one candidate ZIP and
its `.sha256` sidecar.

The release-candidate script already requires two clean, byte-identical local
builds and matching public-vector self-tests. That local equality is not the
independent comparison with the GitHub candidate; the next step performs it.

## Compare with the reference

Run:

```console
python3 scripts/test_verify_independent_reproduction.py
python3 scripts/verify_independent_reproduction.py \
  --reference-artifact reference-github-artifact.zip \
  --reference-artifact-sha256 <64-lower-case-hex-digest> \
  --reproduced-archive \
    dist/tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip \
  --expected-commit <40-lower-case-hex-commit> \
  --expected-target x86_64-unknown-linux-gnu \
  --report reproduction-report.json
```

The reproduced sidecar defaults to `<reproduced-archive>.sha256`. Supply
`--reproduced-sidecar` only when it is stored elsewhere.

The command fails if the reference digest, sidecars, archive structure, package
identity, source timestamp, public documents, metadata-declared executable hash,
or raw executable bytes differ.

ZIP hashes may legitimately differ across Python or zlib versions even when the
uncompressed package contents and executable bytes agree. Raw executable
comparison is authoritative.

`rustc --version --verbose` and `cargo --version --verbose` metadata are hashed
and compared in the report but do not by themselves make a byte-matching
executable fail. Cargo's verbose output can include host operating-system,
OpenSSL, libcurl, and other environment details. Every reported toolchain
metadata difference must therefore be explained and reviewed; it is not silently
ignored.

## Optional packaged self-test

After reviewing the reproduced executable, append:

```console
--execute-reproduced-self-test
```

The helper then runs only:

```text
<reproduced-binary> self-test --json
```

The report must use the declared self-test schema, contain at least one check,
and state `public_vectors_only: true` and `passed: true`. No user wallet material
is generated or requested.

This execution remains unsandboxed. Omitting the flag keeps the entire helper in
inspection-only mode.

## Privacy-safe report

The JSON report contains only:

- frozen commit and target;
- artifact, archive, executable, and toolchain-metadata hashes;
- candidate filenames rather than local paths;
- equality results;
- optional reproduced self-test status;
- coarse Python/operating-system family and architecture; and
- explicit limitations.

It intentionally omits usernames, hostnames, absolute paths, environment dumps,
mnemonics, passphrases, seeds, xprvs, account xpubs, descriptors, addresses,
fingerprints, wallet files, and transaction history.

Use [the evidence template](REPRODUCTION_REPORT_TEMPLATE.md) and review every
report and transcript before publication.

## Review and mismatch handling

A second reviewer should check:

- the frozen commit, target, reference artifact, digest, and attestation;
- independent source acquisition and separate administration;
- complete operating-system, compiler, linker, Cargo, Python, and dependency
  details;
- a clean source tree and exact commands;
- raw executable equality;
- any toolchain metadata or archive difference;
- optional reproduced self-test evidence;
- absence of wallet secrets and private machine data; and
- that no unsupported target claim was inferred.

A mismatch is evidence to investigate, not something to strip, normalize, or
exclude after seeing the result. Compare source tree, lockfile, target triple,
Rust/Cargo/linker versions, `RUSTFLAGS`, `SOURCE_DATE_EPOCH`, incremental-build
settings, generated files, locale, and operating-system differences. Keep the
target unsupported until the cause is explained and a reviewed reproduction
succeeds.

## Completion boundary

Issue #7 may be closed only after independently administered Linux, macOS, and
Windows reproductions satisfy its acceptance criteria and another reviewer has
checked the evidence.

A maintainer-run helper invocation, a copied candidate used as both inputs, or
another GitHub-hosted job does not satisfy that gate. Recovery drills under issue
#8 and the independent assessment under issue #9 remain separate blockers before
`0.1.0`.
