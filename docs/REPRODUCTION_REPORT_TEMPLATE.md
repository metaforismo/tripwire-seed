# Independent reproduction evidence template

Complete one copy per native target. Publish only after a second reviewer has
checked it against `docs/INDEPENDENT_REPRODUCTION.md`.

```text
Repository: https://github.com/metaforismo/tripwire-seed
Frozen commit:
Native target:
Reference workflow run:
Reference artifact ID and name:
Reference outer artifact SHA-256:
Reference candidate archive SHA-256:
Reference executable SHA-256:
Reference attestation identifier or URL:

Reproduction operating system and version:
Architecture:
Rust/rustup version:
rustc --version --verbose:
cargo --version --verbose:
LLVM or native linker version:
Python version:
Git version:
Dependency preparation method:
Source acquisition and verification method:
Relevant build environment variables:
Build command:

Source tree clean before build: yes/no
Two local clean builds identical: yes/no
Public-vector self-tests identical and successful: yes/no
Reference artifact and sidecar validation successful: yes/no
Public package documents identical: yes/no
Identity and toolchain metadata identical: yes/no
Raw executable bytes identical: yes/no
Reproduced packaged self-test explicitly executed: yes/no
Reproduced packaged self-test successful: yes/no/not executed
Archive or environment differences explained:

Operator identity or pseudonym:
Independent reviewer identity or pseudonym:
Reviewer checked administrative independence: yes/no
Reviewer checked hashes and report: yes/no
Date:
Limitations or inconclusive areas:
```

Do not include local usernames, hostnames, home-directory paths, mnemonic words,
BIP39 passphrases, seeds, xprvs, account xpubs, descriptors, addresses,
fingerprints, wallet files, device identifiers, or wallet history.

A completed sheet for one target does not establish the other two targets,
wallet interoperability, or an independent security audit.
