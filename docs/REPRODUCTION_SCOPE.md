# Independent reproduction scope

The first stable-release reproduction claim is scoped to these native targets:

- `x86_64-unknown-linux-gnu`;
- `aarch64-apple-darwin`; and
- `x86_64-pc-windows-msvc`.

Each target requires its own frozen commit, reference artifact, separately
administered build environment, raw executable comparison, privacy-safe report,
and independent review. Evidence for one target cannot be reused as evidence for
another.

Archive equality is not required because ZIP compression can differ across
Python or zlib versions. The complete raw executable bytes and declared public
package contents are the authoritative comparison surfaces.
