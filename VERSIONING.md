# Versioning

Wire releases use semantic version tags.

- `v0.x.y`: bootstrap releases. Breaking changes require explicit review and a
  coordinated update plan for every consumer.
- `v1.x.y`: stable V1 wire. Backward-incompatible changes require a new major
  version or a new protobuf package version.

Every release publishes an immutable `wire.binpb` descriptor image. Consumers
must pin an exact tag or descriptor digest; they must not track `main`.

The first release should remain `v0.x` until Node, Builder, Cortex, and SDK all
build successfully from the same descriptor and one complete localnet workflow
has passed.
