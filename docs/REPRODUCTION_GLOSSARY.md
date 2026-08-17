# Reproduction assurance terms

**Same-runner double build**
: Two clean builds in one runner environment produce identical executables.

**Reference artifact integrity**
: A downloaded GitHub artifact matches a separately obtained outer digest, its
  embedded sidecar, and, where applicable, a provenance attestation.

**Raw executable equality**
: The complete reproduced executable byte sequence matches the reference
  executable byte sequence. This is stronger than matching selected sections and
  separate from ZIP equality.

**Independent reproduction**
: A separately administered system obtains a reviewed frozen source target,
  builds it under a recorded environment, matches the reference executable, and
  receives second-person review.

**Reproducible-build proof**
: The combined evidence and review supporting a scoped claim that independent
  parties can recreate the declared artifact. One helper invocation is not such
  a proof.

**Public-vector self-test**
: Deterministic known-answer checks containing no user wallet material. Success
  checks packaged implementation behavior but does not authenticate the binary.
