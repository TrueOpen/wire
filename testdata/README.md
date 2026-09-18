# Wire Test Vectors

This directory stages language-neutral wire fixtures for Node, Nexus,
Cortex, and SDK implementations.

Most `v1` files are exact-byte copies from the Node commit recorded in
`v1/manifest.json`, and name in `source_path` the file they were copied from. The
rest carry `"origin": "wire"` and were authored here because no upstream file
exists to copy; they name in `contract_section` the monorepo section a reviewer
checks them against. During bootstrap, Node keeps its existing copies and tests.
Importing these files does not change a consumer dependency or make wire
fixtures authoritative by itself.

Until consumer cutover:

- do not edit a wire fixture without updating and reviewing the Node parity;
- do not regenerate expectations from one language implementation without an
  independent wire review;
- verify file bytes against `manifest.json` before publishing a wire release.

After cutover, consumers must pin a wire release and verify these vectors
from that release rather than maintaining independent copies.
