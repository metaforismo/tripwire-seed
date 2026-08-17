# Independent reproduction checklist

- [ ] Freeze one immutable commit and native target.
- [ ] Record the GitHub workflow run, artifact ID, outer digest, and attestation.
- [ ] Obtain and review the source through a documented independent channel.
- [ ] Record the separately administered build system and complete toolchain.
- [ ] Confirm a clean source tree and committed lockfile.
- [ ] Run the native double-build candidate procedure.
- [ ] Compare the result with `verify_independent_reproduction.py`.
- [ ] Explain every mismatch without post-hoc stripping or normalization.
- [ ] Optionally execute only the reproduced public-vector self-test after review.
- [ ] Remove all local paths, host details, and wallet material from evidence.
- [ ] Obtain a second review of hashes, procedure, and administrative independence.
- [ ] Keep issue #7 open until all three native targets qualify.

See [the full procedure](INDEPENDENT_REPRODUCTION.md) and
[the evidence template](REPRODUCTION_REPORT_TEMPLATE.md).
