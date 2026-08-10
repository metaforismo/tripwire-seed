# Contributing

Security and recovery correctness take priority over feature velocity.

## Before opening a pull request

1. Discuss behavioral or cryptographic changes in an issue first.
2. Use only official public test vectors or disposable unfunded data.
3. Explain every dependency addition and why the standard library or an existing
   dependency is insufficient.
4. Update the threat model and cryptographic design when a trust boundary or
   invariant changes.
5. Run the full local verification suite:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo audit --deny warnings
cargo deny check
```

## Coding rules

- Keep `unsafe` code forbidden.
- Never accept secrets through CLI arguments or environment variables.
- Never add telemetry or runtime network access.
- Treat xpubs and descriptors as privacy-sensitive even though they cannot spend.
- Keep secret display and persistence opt-in, explicit, and independently
  confirmed.
- Refuse overwrite rather than adding a force flag.
- Do not claim entropy for human choice.
- Add negative tests for every secret-handling boundary.

## Pull requests

Keep changes focused. Describe user-visible behavior, security impact, test
evidence, and remaining limitations. Passing CI is necessary but not sufficient
for merge; cryptographic changes require human review against the cited
specification.
