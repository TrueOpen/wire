# Wire Test Vectors

This directory stages language-neutral wire fixtures for Node, Nexus,
Cortex, and SDK implementations.

Most `v1` files are exact-byte copies from the Node commit recorded in
`v1/manifest.json`, and name in `source_path` the file they were copied from. The
rest carry `"origin": "wire"` and were authored here because no upstream file
exists to copy; they describe in `contract_section` the public behavior a reviewer
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

## Integers above 2^53

JSON numbers in these files are exact decimal integers, and some exceed 2^53,
the largest integer an IEEE-754 double represents exactly. Today three fields
carry `18446744073709551615` (u64 max) as a bare JSON number:

- `shared/framing_v1.json`, vector `single_uint64_max`, its `uint64` field;
- `shared/params_v1.json`, the `price_hard_max` leaf of the parameter tree;
- `hub/hub_domains_v1.json`, the `upper_work_units_inclusive` leaf of a
  timeout bucket entry.

A reader whose default JSON number type is a double (JavaScript
`JSON.parse`, Python with a float hook, Go decoding into `any` without
`UseNumber`) silently turns that value into `18446744073709551616`, which
then fails to encode as a u64 or encodes the wrong bytes. Decode these files
with an exact integer type: Go `json.Decoder.UseNumber` or a typed `uint64`,
Python's default `int`, or a JavaScript parser with a BigInt reviver. The
values stay numbers because existing decoders read them as numbers; changing
them to strings would break those decoders. `task/order_economics_v1.json`,
whose amounts routinely exceed 2^53, writes every amount as a decimal string.
