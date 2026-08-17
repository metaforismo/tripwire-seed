# Evidence, mismatches, and completion

## Handle a mismatch

A raw executable mismatch is a result, not permission to hide the difference.
Preserve both original archives, sidecars, and reports. Record the source commit
and acquisition method; Rust, Cargo, LLVM/linker, Python, OS, and architecture;
dependency preparation; controlled build variables and commands; both executable
hashes; and the first evidence-backed explanation for the difference.

Platform tools such as `diffoscope`, `readelf`, `objdump`, `otool`, `codesign`,
`dumpbin`, or PE inspection may help. Analyze only disposable public binaries.
Do not close a target by stripping sections, ignoring one platform, changing the
source after seeing the result, or comparing a normalized derivative instead of
the raw executable.

## Privacy-safe public packet

Public evidence may contain the repository URL and frozen commit, target and
artifact identifiers, archive and executable hashes, tool and OS versions,
controlled commands and non-secret variables, comparison booleans, public
self-test check names, mismatch analysis, and a voluntarily disclosed reviewer
identity or pseudonym.

It must not contain mnemonic, BIP39 passphrase, seed, xprv, private key, SeedQR,
plaintext secret export, account xpub, descriptor, fingerprint, address,
watch-only JSON, wallet file, transaction history, local username, hostname,
home directory, unrelated path, environment secret, token, credential, signing
key, production screenshot, terminal recording, or support bundle.

The helper redacts common host-specific values and refuses absolute paths in
candidate tool metadata. Review every report before publication; automated
redaction is not an infallible privacy proof.

## Per-target completion

One target may be marked reproduced only after a separately administered system
builds the exact frozen source; the raw executable matches the reference; the
local reproduced executable passes public vectors; environment and transfer
notes are privacy-safe; every mismatch is explained; and another reviewer checks
the commit, hashes, report, and notes.

Issue [#7](https://github.com/metaforismo/tripwire-seed/issues/7) may close only
after Linux, Apple Silicon macOS, and 64-bit Windows satisfy those conditions for
the same final release target. Recovery drills and independent security review
remain separate gates.
