# Reproduction verifier trust boundaries

The independent-reproduction verifier is designed to parse hostile archive and
metadata inputs without extracting the reference candidate. Its default mode
performs no executable launch.

Security-relevant invariants:

- input files are size bounded and must be regular files;
- ZIP member counts, uncompressed sizes, names, types, timestamps, and modes are
  validated before comparison;
- duplicate, absolute, drive-qualified, encrypted, non-regular, traversing, and
  ambiguous members are rejected;
- candidate metadata has an exact versioned field set and duplicate JSON keys are
  rejected;
- reference and reproduced sidecars must commit to their complete candidate
  archives;
- the frozen commit and target are required explicitly;
- raw executable equality is authoritative, not ZIP compression equality;
- the reference executable remains in memory and is never executed;
- executing the reproduced binary requires explicit opt-in, runs with current
  user privileges, and is not sandboxed; and
- the emitted report excludes local paths, hostnames, usernames, and wallet
  material.

The verifier cannot establish administrative independence, authenticate source
acquisition, attest the local toolchain, detect a compromised operating system,
or replace external reviewer judgment. Those properties are procedural gates in
issue #7 rather than software assertions.
