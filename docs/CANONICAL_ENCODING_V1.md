# Canonical Encoding V1

Status: bootstrap copy from `TrueOpen/node@119ad228af6239e197ad29a3103cc21fdfab9873`.

The machine-readable framing registry is `registry/v1/framing.json`. The
language-neutral test vectors under `testdata/v1` remain the executable
compatibility boundary during bootstrap.

## Primitive Encodings

- `uint32` and enums use exactly four big-endian bytes.
- `uint64` uses exactly eight big-endian bytes.
- signed integers use fixed-width two's-complement big-endian bytes.
- booleans use one byte: `00` for false and `01` for true.
- Hash32 values enter preimages as raw 32 bytes, not hex or base64 text.
- addresses enter preimages as address-codec bytes, not Bech32 text.
- strings are strict UTF-8 bytes with no trimming or Unicode normalization.
- optional values use a presence byte followed by the value when present.
- repeated values bind a count and then their contract-defined ordered elements.
- oneof values bind the selected protobuf field number before the selected payload.

CSV, delimiter concatenation, formatted text, protobuf marshal bytes, and
unordered JSON are not canonical consensus encodings.

## H_V1

One opaque payload uses:

```text
ascii("TRUEOPEN_FRAME_V1")
|| u32_be(len(domain)) || domain
|| u64_be(len(payload)) || payload
```

`H_V1` is SHA-256 over those exact bytes.

## H_FIELDS_V1

An ordered typed tuple uses:

```text
frame(domain) || frame(field_1) || ... || frame(field_n)
frame(value) = u64_be(len(value)) || value
```

`H_FIELDS_V1` is SHA-256 over those exact bytes. The ordered field list for each
business domain is recorded in `registry/v1/domains.json`.

## MERKLE_ROOT_V1

The Merkle domain frame is `u32_be(len(domain)) || domain`.

- leaf: `SHA256("TRUEOPEN_MERKLE_LEAF_V1" || domain_frame || raw_hash32_leaf)`
- node: `SHA256("TRUEOPEN_MERKLE_NODE_V1" || domain_frame || left || right)`
- empty: `SHA256("TRUEOPEN_MERKLE_EMPTY_V1" || domain_frame)`

An odd final node is promoted unchanged. The primitive never sorts,
deduplicates, or pads leaves; the owning business contract defines leaf order.

## Canonical JSON

Canonical JSON accepts UTF-8 object keys and strings, arrays, booleans, and
non-negative integer values. It rejects null, floating-point values, negative
integers, byte slices, and implementation-specific objects. Object keys use
deterministic UTF-8 lexical order and HTML escaping is disabled. No trailing
newline is part of the canonical payload.

## Signatures

Protocol signatures use a compressed 33-byte secp256k1 public key and a compact
64-byte `R||S` signature. Signature hex is lowercase without a prefix. `R` and
`S` must be non-zero and in range, and `S` must be low-S. DER, uppercase hex,
and 65-byte recoverable encodings reject.

The owning domain determines whether the signed input is a message or an
already-derived Hash32. A signature digest is `SHA256(raw_signature_64)` and
never hashes the hexadecimal text.

## Bootstrap Authority

These files record current implemented behavior; they do not silently resolve
known contract gaps. Entries marked unregistered or divergent in
`registry/v1/domains.json` remain non-frozen until reviewed and corrected before
the stable Wire V1 release.
