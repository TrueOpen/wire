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

## Cutting a release

A tag is permanent. Once any Go consumer has fetched a version, the Go module
proxy and checksum database keep that content for good: moving the tag later
hands consumers the stale content or fails with a checksum mismatch. Every
consumer is therefore verified against the release candidate **before** the tag
is pushed.

1. Open the release pull request (changelog heading renamed to the version) and
   push its branch. Do not tag.
2. Run the release path locally against the candidate commit. First,
   `release/notes.sh <version>` must print the new section; the release job
   publishes exactly that text and fails without it. Then: `buf breaking`
   against the previous release, and `tools/release-manifest` in write and
   verify mode. The previous release must be picked as the baseline.
3. Point each consumer at the candidate commit on a local branch and run its
   full test suite:
   - Node and Cortex: `go get github.com/TrueOpen/wire@<commit>`, then
     regenerate and test;
   - SDK: move the `third_party/wire` submodule to `<commit>`, regenerate and
     test.
4. If a consumer finds a mismatch, fix it here, push, and repeat step 3 against
   the new commit. Nothing is published yet, so this costs nothing.
5. Once every consumer passes, merge the release pull request, wait for `main`
   to go green, and tag the merge commit.
6. Consumers switch their pins from the commit to the tag before merging a
   pin update for a release.

A consumer may merge a pin to a commit on wire `main` only to consume
additive, unreleased material it needs now (for example new test vectors),
and only when that commit is on `main` rather than a branch. It must say so
where it records the pin, and move to the next wire tag once one exists.
That commit must add to the last tag only: no proto field, domain, framing or
existing digest may differ from it.

Not every mismatch needs a release. A change that alters a digest, a preimage,
framing or a signature is fixed in wire and released. A descriptive error in a
fixture that leaves every digest and byte intact may be carried by the consumer
as a narrowly scoped exception that fails once wire corrects it, and batched
into the next release.

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
