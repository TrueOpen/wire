# TrueOpen Wire

Wire definitions, signing domains, framings and cross-language fixtures for
TrueOpen Node, Builder, Cortex and SDK.

## Scope

This repository owns the language-neutral wire definitions under `proto/`:

- `shared.v1`: common amounts, evidence, model profiles, payloads,
  pagination, and every enum or message more than one domain reads. It is a
  descriptor import leaf and imports no other package this repository owns.
- `hub.v1`: Hub messages, queries, events, parameters, and state schemas.
- `task.v1`: Task messages, queries, events, parameters, and state schemas.
  It has no direct or transitive proto import of `hub.v1`.
- `bus.v1`: the nexus <-> cortex NATS task-control envelope and payloads.
  It imports `shared.v1` and `task.v1` only.

Generated Node Go sources, Node OpenAPI assembly, Keeper validation, and service
implementations remain in their consumer repositories.

## Validation

The repository pins Buf `v1.71.0` in CI.

```sh
go run github.com/bufbuild/buf/cmd/buf@v1.71.0 lint
go run github.com/bufbuild/buf/cmd/buf@v1.71.0 build -o build/wire.binpb
```

Pull requests are checked for breaking changes against `main`. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [VERSIONING.md](VERSIONING.md).

## Compatibility Assets

- `registry/v1`: canonical framing and domain registry bootstrap snapshots.
- `testdata/v1`: language-neutral positive, tamper, replay, and hash vectors.
- `schemas`: machine-readable manifests and registry schemas.
- `gen`: pinned TypeScript and OpenAPI compatibility generation profiles.
- `release`: release manifest policy. A release is cut by pushing a `v*` tag;
  see [release/README.md](release/README.md) and [VERSIONING.md](VERSIONING.md).

`source_repository` and `source_commit` in `registry/v1/domains.json`,
`registry/v1/framing.json` and `testdata/v1/manifest.json` record bootstrap
provenance only. `source_commit` names a commit of `source_repository`
(TrueOpen/node), not of this repository, and pins the rows and files that were
copied from it unchanged: registry rows without an `origin`, and fixtures with
`origin: node`. That commit is not reachable in the public history of
`source_repository`, so it cannot be used to fetch or diff anything; tooling
checks only its form and that the two registries agree on it. Everything this
repository authored or changed since carries its own provenance (an `origin`
with a review link, or `origin: wire` with a `contract_section`), and what a
consumer verifies is the release: the release manifest names every registry and
fixture file by size and SHA-256.

See [Canonical Encoding V1](docs/CANONICAL_ENCODING_V1.md) for the current
implemented framing boundary. Entries marked unregistered or divergent remain
non-frozen until reviewed.
