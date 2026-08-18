# Coverage-guided fuzzing

`tripwire-seed` keeps its runtime offline, but it still parses attacker- or
operator-controlled public metadata. The repository therefore fuzzes only
public, non-secret surfaces and does not generate or ingest user wallet secrets.

## Target

The `public_surfaces` libFuzzer target covers three related boundaries:

1. arbitrary UTF-8 strings are passed through BIP380 descriptor checksum
   calculation and checksum-appending logic;
2. arbitrary bytes are decoded directly into the strict `TripwireSummary` JSON
   data model; and
3. successfully decoded summaries are passed through semantic validation and the
   domain-separated watch-only fingerprint implementation.

For semantically valid summaries, the target additionally requires the freshly
computed fingerprint to verify in both lower- and upper-case hexadecimal form.

The maximum generated input is 64 KiB, matching the watch-only file-size safety
boundary used by the CLI. The target does not write files, open the network,
read the operating-system CSPRNG, display a SeedQR, or request a mnemonic or
BIP39 passphrase.

## Corpus

The committed seed corpus is intentionally public. It includes:

- the official BIP380 `raw(deadbeef)` descriptor vector;
- the same descriptor with its checksum already appended, exercising the
  second-checksum rejection path; and
- a complete, semantically valid BIP84 watch-only reference built from the
  public BIP84 test vector with identical decoy/protected account xpubs.

A normal Rust regression parses and validates these committed seeds, so a corpus
file cannot silently stop exercising its intended success/rejection branch.

## CI policy

Pull requests that change the fuzz workspace, descriptor logic, watch-only data
model, semantic validator, fingerprinting, or fuzz workflow run a short
coverage-guided campaign. Pushes to `main` run the same gate, and a scheduled
weekly campaign receives a longer time budget.

The workflow pins:

- a dated Rust nightly toolchain;
- an exact `cargo-fuzz` version;
- exact direct versions for the fuzz-only dependencies; and
- a committed `fuzz/Cargo.lock` for the complete fuzz dependency graph.

Before fuzzing, `cargo metadata --locked` must accept the committed fuzz
lockfile. After the campaign, CI requires `fuzz/Cargo.lock` to remain byte-for-
byte unchanged in the worktree. This makes an accidental dependency re-resolution
a failing gate instead of an implicit runner-side update.

The fuzz workspace is included in Dependabot and `cargo-deny` checks. The
`libfuzzer-sys` package declares `(MIT OR Apache-2.0) AND NCSA`; `deny.toml`
therefore permits `NCSA` only for the exact `libfuzzer-sys@0.4.13` package rather
than adding NCSA to the repository-wide allow list. The fuzz workspace is not
part of the shipped binary and does not change the application's dependency
graph.

## Run locally

Install the same nightly and pinned `cargo-fuzz`, verify the lockfile, then run:

```console
cargo +nightly-2026-08-12 metadata \
  --manifest-path fuzz/Cargo.toml \
  --locked \
  --format-version 1 >/dev/null

cargo +nightly-2026-08-12 fuzz run public_surfaces \
  fuzz/corpus/public_surfaces \
  -- -max_total_time=30 -timeout=5 -max_len=65536

git diff --exit-code -- fuzz/Cargo.lock
```

Fuzz artifacts and crashes may contain mutated public metadata. They must still
be reviewed before publication because mutations can accidentally include local
paths or operator-added corpus material. Never seed the corpus with a real
mnemonic, BIP39 passphrase, xprv, private key, production account xpub,
descriptor, address, or wallet file.

## Assurance boundary

A green fuzz campaign is evidence that the exercised inputs did not trigger a
crash or violate the encoded invariants during that campaign. It is not a proof
that the parser is bug-free, it does not cover secret-handling terminal paths,
and it does not replace the independent review or recovery drills required by
the stable-release gate.
