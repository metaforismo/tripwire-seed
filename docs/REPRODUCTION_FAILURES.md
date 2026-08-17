# Handling reproduction mismatches

A mismatch is evidence to investigate. Do not make the result pass by stripping,
normalizing, excluding a target, changing the expected digest, or rebuilding
until one output happens to agree.

Record privacy-safe hashes and compare, in order:

1. frozen source commit and complete source tree;
2. committed lockfile and dependency source/cache;
3. Rust, Cargo, LLVM, native linker, Python, and operating-system versions;
4. target triple and native linker mode;
5. `RUSTFLAGS`, `SOURCE_DATE_EPOCH`, and incremental-build settings;
6. build scripts, generated files, locale, and environment;
7. raw executable sections and build identifiers; and
8. package metadata and public documents.

Keep the failed target unsupported until the cause is understood, a reviewed fix
exists where necessary, and a new independently administered reproduction
succeeds. Never publish wallet secrets, complete wallet metadata, usernames,
hostnames, or unrelated local paths while diagnosing the mismatch.
