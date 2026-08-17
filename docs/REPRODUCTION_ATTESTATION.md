# Attestation use in reproduction

GitHub provenance attestations identify candidate archives produced by the
main-branch workflow. Verify them separately with GitHub's supported tooling and
record the attestation identifier in the evidence sheet.

The local comparison helper intentionally does not implement its own attestation
client. Reimplementing GitHub identity, OIDC, transparency, and signature
verification inside a small standard-library script would create a second trust
implementation and a misleading assurance surface.

Attestation verification establishes reference provenance within GitHub's trust
model. It does not prove that the source, runner, compiler, dependencies, or
independent build system were uncompromised.
