# Wire Releases

A release is cut by pushing a `v*` tag. The `release` job in
`.github/workflows/contract.yml` runs only after the `contract` job passes, so
the bootstrap assets, service schemas, cross-language generation and
compatibility gates are all green before anything is published.

Each release publishes:

- `wire.binpb` and `wire.binpb.sha256` — the descriptor image, rebuilt from the
  tagged tree rather than reused from an earlier run;
- `release-manifest.json` — conforming to
  `schemas/release-manifest-v1.schema.json`, naming every published artifact by
  size and SHA-256 so a consumer can verify a download without trusting the
  release page;
- `registry/v1/domains.json`, `registry/v1/framing.json` and
  `testdata/v1/manifest.json` — the registry and fixture checksums the manifest
  refers to;
- the `buf breaking` result against the previous release, recorded in the
  manifest's `compatibility` field (`bootstrap` for the first release, `pass`
  plus `against_version` afterwards);
- changelog entries and known contract gaps.

`tools/release-manifest` both writes and verifies the manifest, and the `contract`
job runs it in dry-run mode on every push and pull request. A release manifest
that first executes while a tag is being cut is a release-day surprise; the
dry-run means the whole path is already proven when the tag lands.

## Release scope

`release/packages.json` declares which proto packages a release publishes as
frozen and which are deliberately withheld. `tools/release-manifest` freezes it
against the proto tree in both directions: `released` plus `withheld` must equal
exactly the packages present under `proto/`, and the two must be disjoint. A new
package therefore cannot be published by accident, and cannot be dropped by
accident either.

A withheld package stays in `proto/` and keeps passing `buf lint` and
`buf breaking`. Withholding says only that its fields are not frozen yet, so the
release makes no compatibility promise about it.

Withholding exists so that one unresolved upstream decision does not hold the
whole contract hostage. `v0.1.0` withholds `bus.v1` for the two open items
recorded in `release/packages.json`; Node consumes no `bus` package, so the
Node import path is unaffected.

## Node import

Node imports the released `wire.binpb`, not the `.proto` sources: generating Go
from the descriptor image produces byte-identical output to generating from the
sources, so the single published artifact is enough and no consumer needs a copy
of `proto/`.

Until the first release lands, `proto/` in this repository is a manual copy of
`TrueOpen/node`'s `proto/`, and **node is the authoritative source**. The two
trees are descriptor-identical today. After the cutover the direction reverses:
this repository becomes the source and node generates from the release artifact.
