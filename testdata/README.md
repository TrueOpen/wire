# Wire Test Vectors

`v1/task/session_key_authorization_v1.json` contains wallet and delegated
signatures over the same order digest, registered-key requests with no
SessionGrant, and admission/SET/CLEAR cases. It covers inclusive expiry,
re-registration anchor isolation, rotation, cap boundaries, zero-cap unlimited
mode, checked accumulation, rollback and accepted-task continuation. Amounts
in these cases are exact decimal strings. The current registration limit and
historical zero in update cases demonstrate that the limit is read from live
parameters; they are fixture values, not network defaults. The registered request
cases also pin state/key-before-expiry-before-method failure ordering, missing
local Task lookup and OUTPUT-only Task Data access.

`v1/task/session_key_amino_v1.json` pins registration signing bytes for creation,
SET and boolean CLEAR: canonical Amino JSON, the complete Web3 typed graph,
domain/hash/digest and a recoverable wallet signature. Byte fields in this
signing projection are Base64, not the REST Hash32 form. CLEAR is `true`, not an
empty struct; consumers must check the independent digests, not only that three
actions produce different hashes.

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

## Phase 1 byte conformance

`v1/task/dispatch_v1.json` includes independent signing projections, real low-S
signatures and ELL2 proof, full-pool weighted ordering, operation isolation,
challenge scopes and exact typed Builder evidence linked to content/evidence/fault
IDs. `value_evidence_v1.json` pins both bounded opening payloads and digest
projections. `session_funding_amino_v1.json` freezes funding/withdrawal wallet
signatures, including boolean CLOSE. These establish bytes, not Task admission:
consumer authority, escrow and complete localnet acceptance remain required.
