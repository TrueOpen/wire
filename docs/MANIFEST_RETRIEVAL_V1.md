# Manifest Retrieval V1

The chain stores a model profile's `manifest_hash` and a retrieval pointer,
`ProfileState.manifest_uri`, returned together by `hub.v1.Query/Profile`. The
manifest body itself is hosted by the registrant. This page states how a client
(SDK, Cortex, indexer) turns the pointer into a verified manifest.

`manifest_uri` is a hint, not a trust source. Trust comes only from
`manifest_hash`: a fetched body that does not hash to it is discarded, and a
dead URI costs availability, never correctness.

## Where it lives

- `shared.v1.ModelProfileProjection.manifest_uri` (field 23): set by the
  registrant at registration. It is part of the projection, so it enters
  `TRUEOPEN_MODEL_CHAIN_PROJECTION_V3` and, through `chain_projection_hash`,
  `TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3`.
- `hub.v1.ProfileState.manifest_uri` (field 34): the stored copy, frozen with
  the profile version.
- It is **not** inside the manifest and does **not** enter `manifest_hash`.
  When a reader rebuilds the projection from a fetched manifest (for example to
  recompute `chain_projection_hash`), it takes `manifest_uri` from the chain.
- `hub.v1.ModelParamsV1.max_manifest_uri_bytes` (field 12) caps its length.

## Syntax

Checked by the Keeper at registration without fetching, and kept byte for byte:
it is hashed, so no implementation may normalize it. Printable ASCII
(0x21-0x7E) only, length `1..max_manifest_uri_bytes`, and either

```text
https:// host [":" port] [path] ["?" query]     no userinfo, no fragment
ipfs://  CID [path]                             CIDv0 base58btc or CIDv1 lowercase base32
```

Every varint inside a CIDv1 (version, content codec, multihash function code,
digest length) must be minimally encoded and at most 9 bytes.

`testdata/v1/hub/manifest_uri_v1.json` is the reference: every accepted and
rejected form, and the strict reading taken wherever the rule leaves room.

## Fetch order

1. Local cache, keyed by `manifest_hash`.
2. `ProfileState.manifest_uri`.
3. Optional mirrors: any service that serves the same bytes by
   `manifest_hash`.

Every source is verified the same way (below); a failure moves on to the next.

## Processing order

1. Read the body with the bounds below (size counted after decompression).
2. Compute `H_V1("TRUEOPEN_MODEL_MANIFEST_V4", bytes)` and compare it with
   `manifest_hash`. Mismatch: discard.
3. Parse strictly and validate the manifest schema.
4. Re-encode the parsed manifest canonically; the result must equal the fetched
   bytes exactly.
5. Compare the manifest's projection fields with the on-chain `ProfileState`.

A hash match proves only that these are the bytes the registrant committed to,
not that they are a valid manifest. Never parse and re-canonicalize first to
make a hash match.

## Downloader obligations

The hash check happens after the download, so the request itself must be
constrained. A default downloader must:

- [ ] Resolve the host and refuse loopback, private, link-local, unique-local
      and cloud-metadata addresses, for both IPv4 and IPv6.
- [ ] Connect to the address it checked; never let the HTTP client resolve the
      name a second time (DNS rebinding).
- [ ] Re-resolve and re-check on every retry and every redirect hop.
- [ ] Follow at most 3 redirects, and never from `https` to `http`.
- [ ] Verify TLS against the original hostname.
- [ ] Apply a connect timeout and a total timeout.
- [ ] Bound the body by `Content-Length` and by the bytes actually read, both
      at `max_manifest_bytes` = 4 MiB (4,194,304 bytes); abort beyond it
      without parsing.
- [ ] Count a compressed response at its decompressed size against the same
      bound; accept no decoding other than standard transfer compression.
- [ ] Fetch `ipfs://` through a local or trusted gateway under the same size
      and time limits.

## Test scenarios implementers must cover

- A body whose hash matches: accepted.
- A body with the wrong hash: discarded, next source tried.
- A body that hashes correctly but is not canonical JSON, or fails schema
  validation: rejected.
- `Content-Length` above 4 MiB: aborted before reading the body.
- No or false `Content-Length` with a body above 4 MiB: aborted during reading.
- A small compressed response that decompresses above 4 MiB: aborted.
- A host resolving to 127.0.0.1, ::1, 10.0.0.0/8, 172.16.0.0/12,
  192.168.0.0/16, 169.254.0.0/16 (including 169.254.169.254), fc00::/7 or
  fe80::/10: refused without connecting.
- A name that resolves to a public address at check time and a private one on a
  second lookup: the connection still goes to the checked address.
- A redirect to a private address, a redirect to `http://`, and a fourth
  redirect: each refused.
- A server that stalls after connecting: the total timeout fires.
- A cached body for the same `manifest_hash`: used without a network fetch.
- A projection rebuilt from a fetched manifest: `manifest_uri` taken from the
  chain, and the recomputed `chain_projection_hash` matches.
