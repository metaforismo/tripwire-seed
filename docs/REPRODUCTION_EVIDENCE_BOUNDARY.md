# Reproduction evidence boundary

A successful verifier report supports only the following scoped statement:

> For the declared commit and native target, the validated reproduced candidate
> contained the same raw executable bytes, public package documents, and identity
> and toolchain metadata as the validated GitHub reference candidate.

It does not support any of these statements without additional evidence:

- the source checkout was authentic;
- the build system was independently administered;
- the compiler, linker, operating system, firmware, or GitHub runner was trusted;
- the ZIP archives were byte-identical;
- other native targets reproduced;
- Sparrow, COLDCARD, or Ashigaru recovery succeeded;
- the project received an independent security audit; or
- the software is appropriate for meaningful funds.

Public claims should identify the exact commit, target, operator, reviewer,
environment, artifact hashes, and limitations. Issue #7 remains the normative
completion gate.
