# Freeze and build the target

## Freeze public identifiers

Record before building:

```text
Repository: https://github.com/metaforismo/tripwire-seed
Commit: <full 40-character SHA>
Target: x86_64-unknown-linux-gnu | aarch64-apple-darwin | x86_64-pc-windows-msvc
Reference workflow run:
Reference artifact ID and digest:
Reference candidate ZIP SHA-256:
Reference provenance attestation:
```

Do not use `main`, a moving branch, or an abbreviated commit. The reference and
reproduced candidate must declare the same package, version, full commit, target,
source timestamp, metadata schema, and candidate-only linker flags.

## Review and prepare source

1. Obtain the frozen source through a reviewed channel.
2. Verify the complete commit ID and committed `Cargo.lock`.
3. Review source and release scripts before executing them.
4. Require a clean checkout with no local source, lockfile, workflow, or build
   configuration changes.
5. Record operating-system version, architecture, Rust, Cargo, LLVM or linker,
   Python, dependency preparation, build command, and controlled environment
   variables.

Do not publish usernames, hostnames, absolute paths, shell history, credentials,
or unrelated environment values.

## Verify the reference

Download the target candidate ZIP and matching `.sha256` sidecar from the frozen
main-branch workflow. Verify the sidecar with a trusted hashing tool. When
available, verify GitHub provenance as described in
[`REPRODUCIBLE_BUILDS.md`](../REPRODUCIBLE_BUILDS.md).

Treat the downloaded executable as untrusted. The comparison helper inspects its
ZIP, metadata, public documents, and binary hash but never executes it.

## Build on the separate system

Use the pinned native toolchain and existing candidate command:

```console
python3 scripts/test_reproducible_release.py
python3 scripts/test_compare_reproduction.py
python3 scripts/reproducible_release.py \
  --target x86_64-unknown-linux-gnu \
  --output-dir reproduced
```

Select the native target for the reproducer. The release script performs two
clean locked builds, compares those local executables byte-for-byte, runs fixed
public vectors on both, and writes a candidate ZIP plus checksum sidecar.

Do not patch, strip, normalize, resign, recompress, or transform the executable
before comparison. A mismatch must remain observable.
