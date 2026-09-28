# Versioning

Wire releases use semantic version tags.

- `v0.x.y`: bootstrap releases. Breaking changes require explicit review and a
  coordinated update plan for every consumer.
- `v1.x.y`: stable V1 wire. Backward-incompatible changes require a new major
  version or a new protobuf package version.

Every release publishes an immutable `wire.binpb` descriptor image. Consumers
must pin an exact tag or descriptor digest; they must not track `main`. A
consumer may pin a candidate commit on a local branch to verify a release before
it is tagged, but never merges that pin. A published tag is never moved.

The first release should remain `v0.x` until Node, Builder, Cortex, and SDK all
build successfully from the same descriptor and one complete localnet workflow
has passed.

## Before genesis

Until the network's genesis, compatibility with earlier bootstrap releases is
not a goal. A domain's preimage may therefore be revised in place, within the
same domain generation, without introducing a new generation. Every such
revision must be stated in the CHANGELOG entry of the release that makes it,
naming each revised domain; digests computed for those domains under earlier
releases are superseded, and every implementation must move to that release.

After genesis the generation rule applies strictly: any change to a domain's
preimage requires a new domain generation.
