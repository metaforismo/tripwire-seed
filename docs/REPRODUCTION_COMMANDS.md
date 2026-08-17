# Reproduction command reference

Build one frozen native candidate:

```console
python3 scripts/test_reproducible_release.py
python3 scripts/reproducible_release.py --target <target> --output-dir dist
```

Test the comparison helper:

```console
python3 scripts/test_verify_independent_reproduction.py
```

Compare with the reference artifact in inspection-only mode:

```console
python3 scripts/verify_independent_reproduction.py \
  --reference-artifact <outer-github-artifact.zip> \
  --reference-artifact-sha256 <sha256> \
  --reproduced-archive <candidate.zip> \
  --expected-commit <commit> \
  --expected-target <target> \
  --report <new-report.json>
```

After source and binary review, append `--execute-reproduced-self-test` to execute
only the reproduced public-vector self-test. The reference executable is never
executed.
