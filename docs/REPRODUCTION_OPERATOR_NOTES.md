# Reproduction operator notes

Before starting, close unrelated terminals and avoid commands that print the
complete environment. Keep a minimal command transcript containing public build
information only.

During the run:

- use the frozen commit and committed lockfile;
- avoid production wallet material entirely;
- retain original candidate and sidecar files unchanged;
- run the verifier in inspection-only mode first;
- execute the reproduced self-test only after reviewing the local build;
- preserve mismatch hashes before rebuilding; and
- ask the reviewer to verify evidence rather than rely on a verbal summary.

After the run, inspect every report and transcript for usernames, hostnames,
home-directory paths, temporary paths, device identifiers, wallet metadata, or
secrets before publication.
