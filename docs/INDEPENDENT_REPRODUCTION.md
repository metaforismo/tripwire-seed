# Independent candidate reproduction

This procedure compares one Tripwire Seed executable built on a separately
administered native system with the GitHub reference candidate for the same
immutable commit and target.

A matching report is evidence about bytes. It does not prove that the operator,
source channel, compiler, dependencies, firmware, operating system, or either
build environment was independent or uncompromised.

Issue [#7](https://github.com/metaforismo/tripwire-seed/issues/7) remains open
until Linux, Apple Silicon macOS, and 64-bit Windows have all been reproduced for
the same final release target and another reviewer has checked the evidence.

## Procedure

1. [Freeze and build the exact target](reproduction/BUILD.md).
2. [Validate and compare both candidates](reproduction/COMPARE.md).
3. [Prepare privacy-safe evidence and reviewer sign-off](reproduction/EVIDENCE.md).

## Required separation

A valid reproduction is not a second job in the original GitHub Actions
workflow, another runner controlled by that workflow, another target directory
on the original runner, or a comparison of one downloaded candidate with itself.
Use a machine or service administered separately from the original candidate
builder and record who controlled it and how inputs were obtained.

The helper deliberately cannot certify administrative independence. Its reports
always leave these release-level claims false:

```text
administrative_independence_verified
all_supported_targets_complete
stable_release_gate_satisfied
```

The comparison is inspection-only by default. Executing the reproducer's local
public-vector self-test requires an explicit flag; the downloaded reference
binary is never executed.
