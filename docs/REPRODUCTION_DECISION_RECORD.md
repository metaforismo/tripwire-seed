# Reproduction verifier design decisions

- Compare complete executable bytes rather than selected sections.
- Permit candidate ZIP hashes to differ while requiring uncompressed public
  contents and identity/toolchain metadata to match.
- Require a separately supplied outer GitHub artifact digest.
- Parse the reference entirely in memory and never execute it.
- Make reproduced-binary self-test execution explicit and opt-in.
- Use only the Python standard library.
- Emit a bounded, privacy-safe JSON report.
- Leave administrative independence, source authenticity, attestation
  verification, and reviewer sign-off as procedural evidence.

These choices keep the helper narrow and avoid converting convenience tooling
into a stronger assurance claim than it can support.
