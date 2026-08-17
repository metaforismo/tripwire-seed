# Compare the candidates

Run the helper in the same separately administered environment that produced the
reproduced candidate:

```console
python3 scripts/compare_reproduction.py \
  --reference-candidate reference/tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip \
  --reference-checksum reference/tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip.sha256 \
  --reproduced-candidate reproduced/tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip \
  --reproduced-checksum reproduced/tripwire-seed-v0.1.0-x86_64-unknown-linux-gnu.zip.sha256 \
  --report-out tripwire-reproduction-linux.json \
  --execute-reproduced-self-test
```

The helper bounds and validates both archives, rejects unsafe or non-canonical
members and metadata, verifies both sidecars and packaged binary hashes, and
compares exact identity, raw executable bytes, public package documents, source
timestamp, and linker reproducibility flags.

The downloaded reference binary is never executed. The reproducer's local binary
runs `self-test --json` only after the explicit execution flag, in a temporary
directory with a restricted environment. Output must match the strict public
self-test schema, version, and all-pass check set.

## Inspection-only default

Without `--execute-reproduced-self-test`, neither binary executes. The helper
writes an explicitly incomplete report and returns code `3`:

```console
python3 scripts/compare_reproduction.py \
  --reference-candidate <reference.zip> \
  --reference-checksum <reference.zip.sha256> \
  --reproduced-candidate <reproduced.zip> \
  --reproduced-checksum <reproduced.zip.sha256> \
  --report-out inspection.json
```

Use the execution flag only on the separate machine that just built and reviewed
the reproduced candidate. Do not use it to execute a binary obtained from another
party.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Raw executable and required build properties match; local public self-test passed |
| `1` | Input, checksum, archive, metadata, report path, or self-test is invalid |
| `2` | Inputs are valid but a release-relevant comparison differs |
| `3` | Safe inspection completed without executing either binary |

`technical_comparison_complete: true` applies only to this one target and
comparison. It is not administrative-independence proof or stable-release
approval.
