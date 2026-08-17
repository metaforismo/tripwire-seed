# Release-candidate builds and reproducibility

The `Release candidate` workflow produces short-lived native build candidates
for review. It does **not** publish a GitHub release or tag and does not mark the
project stable.

## What the automated gate does

For each native target currently exercised by GitHub-hosted runners:

- `x86_64-unknown-linux-gnu` on Linux;
- `aarch64-apple-darwin` on macOS; and
- `x86_64-pc-windows-msvc` on Windows,

`scripts/reproducible_release.py` performs two clean, locked release builds in
different target directories with incremental compilation disabled and
`SOURCE_DATE_EPOCH` set to the checked-out commit time. The two executables must
be byte-for-byte identical.

Both executables then run:

```console
tripwire-seed self-test --json
```

The reports must be equal and must state that all fixed public-vector checks
passed. No mnemonic, passphrase, seed, account xpub, descriptor, address, or
other user wallet material is requested or generated.

A successful job packages one executable with the README, both licenses, and a
`BUILD-METADATA.json` file. ZIP members are sorted, receive the same normalized
UTC commit timestamp, and use fixed file permissions. A separate `.sha256`
sidecar commits to the complete archive.

Main-branch candidates are also submitted to GitHub's artifact-attestation
service with SLSA build provenance. Pull-request artifacts are deliberately not
attested and the build job has read-only repository permissions.

## What the gate does not prove

A green workflow is useful evidence, but it does not establish all properties
required for a stable release. In particular, it does not:

- authenticate a source checkout obtained through another channel;
- prove that GitHub-hosted runners, the compiler, linker, Python, or dependencies
  were uncompromised;
- prove that an independent machine will reproduce the same executable;
- make ZIP compression byte-identical across different Python/zlib versions;
- test the operating-system CSPRNG, physical dice, terminal, filesystem, swap,
  camera, or malware boundaries;
- replace manual recovery drills with current wallet applications; or
- replace independent cryptographic and implementation review.

The automated result should therefore be described as **same-runner native
double-build reproducibility**, not as a complete reproducible-build proof.

## Candidate contents

Each target artifact contains:

```text
tripwire-seed-v<version>-<target>/
├── tripwire-seed[.exe]
├── BUILD-METADATA.json
├── README.md
├── LICENSE-MIT
└── LICENSE-APACHE
```

The metadata records the package version, exact Git commit, target triple,
commit-derived timestamp, toolchain versions, executable SHA-256, self-test
schema, and successful double-build comparison. It intentionally contains no
runner path, username, hostname, secret, or wallet-derived value.

Artifacts uploaded by CI expire after 14 days and are release candidates only.
Do not redistribute them as an official release.

## Run the same gate locally

Use a reviewed checkout and the repository's pinned Rust toolchain:

```console
python3 scripts/test_reproducible_release.py
python3 scripts/reproducible_release.py \
  --target x86_64-unknown-linux-gnu \
  --output-dir dist
```

On Apple Silicon use `aarch64-apple-darwin`. On 64-bit Windows use
`x86_64-pc-windows-msvc` and invoke the script with `python` if that is the local
launcher name.

The command exits unsuccessfully if the two binaries differ, either self-test
fails, the reports disagree, a required package document is missing, or the
archive/checksum cannot be written.

## Verify a downloaded candidate

First verify the SHA-256 sidecar with a trusted local hashing tool. On GNU/Linux:

```console
sha256sum --check tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip.sha256
```

For a main-branch artifact, GitHub CLI can additionally verify the repository
attestation:

```console
gh attestation verify \
  tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip \
  --repo metaforismo/tripwire-seed
```

Checksum and attestation verification identify the candidate produced by a
particular workflow. They still do not replace source review, independent
reproduction, the packaged-binary self-test, or real recovery drills.
