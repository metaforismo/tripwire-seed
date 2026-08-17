# Reproduction evidence versioning

Every reproduction claim must pin the Tripwire Seed commit, candidate version,
native target, external toolchain, operating system, and reference artifact.

A successful result must not be generalized across:

- a later source commit;
- a different Rust, linker, or operating-system version;
- another native target;
- a changed candidate or report schema; or
- a future release of the verification helper.

When any of those inputs changes, create a new report and retain the earlier one
as historical evidence rather than editing it in place.
