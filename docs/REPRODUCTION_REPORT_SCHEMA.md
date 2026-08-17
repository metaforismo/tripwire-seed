# Reproduction report schema

`tripwire-seed/independent-reproduction-report/v1` contains:

- `inspection_only`;
- frozen `expected.commit` and `expected.target`;
- reference artifact, candidate archive, and executable hashes;
- reproduced candidate archive and executable hashes;
- equality results for executable bytes, documents, and identity/toolchain
  metadata;
- optional reproduced self-test status;
- coarse verifier runtime information; and
- explicit limitations.

The schema deliberately excludes absolute paths, usernames, hostnames,
environment dumps, wallet material, and external-wallet metadata. Consumers must
reject unknown future schema identifiers rather than silently assuming the same
meaning.
