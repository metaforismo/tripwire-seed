## Summary

Describe the behavior and why the change is needed.

## Security impact

- Trust boundaries changed:
- Secret-handling behavior changed:
- Dependencies added or updated:

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-targets --locked`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked`
- [ ] Only official test vectors or unfunded disposable data were used
- [ ] Documentation and threat model were updated where needed

## Remaining limitations

List anything not verified.
