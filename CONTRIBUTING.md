# Contributing

## Contract Rules

- Change wire source here before updating a consumer repository.
- Never reuse a protobuf field number or enum number.
- Reserve removed field names and numbers in the same change.
- Keep existing protobuf package names stable. Moving a symbol between packages
  is a reviewed breaking release, never an incidental change: see the
  reviewed-breaking rules below.
- **Import direction, enforced.** `shared.v1` is a descriptor import leaf -
  it imports Google and Cosmos primitive options and other `shared.v1`
  files, and nothing else - and `task.v1` and `bus.v1` have zero direct
  and zero transitive proto imports of `hub.v1`, with `hub.v1`
  importing `shared.v1` only. This replaces the earlier rule that allowed
  `task` to import `hub`: the module split deliberately superseded it,
  because a cross-domain type parked in an owner package keeps the module split
  from being real, and a Task-owned evidence message that reaches Bus payload
  types through the Hub package closes a Task -> Bus -> Task import cycle in the
  consumer.

  This became true in v0.2.0, which moved fifteen shared symbols into
  `shared.v1`. `tools/verify-import-boundaries` checks it in CI over the
  transitive descriptor closure, so a new `hub.v1` import in a
  `task.v1` or `bus.v1` file - or any non-`shared` import in a
  `shared.v1` file - fails the `contract` job with the exact chain named,
  including when the import is several files deep. Fix the direction rather than
  the check: a symbol two owner packages need belongs in `shared.v1`.
- A cross-domain type - one both an owner package and another owner package
  need - belongs in `shared.v1`. A type only one domain reads stays with
  that domain even if it used to live elsewhere.
- **Every `bytes` field reachable from a registered RPC in `hub.v1.Msg`,
  `hub.v1.Query`, `task.v1.Msg`, `task.v1.Query`,
  `hub.v1.HubEventService` or `task.v1.TaskEventService` carries an
  explicit `shared.v1.rest_bytes_encoding`.** Annotation is per leaf and is
  never inherited by field name; only messages outside all six recursive
  request/response closures may stay unannotated. Native protobuf/gRPC remains
  raw bytes. `tools/verify-rest-encoding` enforces the complete public-service
  closure, while `tools/apply-rest-encoding` projects the HTTP-bound subset into
  generated OpenAPI; both read the same option through
  `tools/internal/protoimage`.
- Include generated descriptor compatibility checks for every wire change.
- Do not commit per-consumer generated code to this repository. The
  canonical Go contract logic (signing projections, verification order,
  replay keys) and its cross-language vectors live here so both consumers
  import one implementation instead of aligning two by hand.

## Reviewed Breaking Releases

The `buf breaking` gate is never disabled and `buf.yaml` carries no
`breaking.ignore` entries. Turning the gate off for one approved break would
also turn it off for every unintended break in the same commit, and an ignore
entry would keep doing so for every release after it.

An approved break is declared instead, in `release/reviewed-breaking.json`:

1. Land the protocol decision first. The declaration has to name a public review a
   reader can follow; a break authorized by nothing is not reviewed.
2. Run the gate and capture its findings:

   ```
   go run github.com/bufbuild/buf/cmd/buf@v1.71.0 breaking \
     --against '.git#tag=<baseline>' --error-format=json > build/breaking.json
   ```

3. Read every finding. This is the review, and it is the only step no tool can
   do for you: the question is whether each finding is a consequence of the
   decision or a mistake that happened to travel with it.
4. Author the declaration:

   ```
   go run ./tools/reviewed-breaking/main.go -findings build/breaking.json \
     -write release/reviewed-breaking.json \
     -version <release> -against <baseline> -review '<the decision>'
   ```

5. Commit it and describe the consumer impact in the pull request.

CI then requires an exact match in both directions: a finding that is not
declared fails the build, and a declared finding that no longer occurs fails it
too, because a declaration that has drifted from the code is no longer evidence
of anything. The declaration authorizes one `protocol_version` against one
baseline; a later tag with a stale declaration is rejected rather than allowed
to inherit the approval. The release manifest records the result as
`reviewed-breaking` with the declaration's digest, never as `pass`.

CI runs that comparison twice: once against the declaration's baseline tag,
exactly as above, and once against `main` with `-subset`. The second one exists
because the baseline sits behind `main` for a whole release. A field this release
added does not exist at the baseline, so deleting it again between merge and tag
produced no finding at all - the break was invisible to the only comparison being
made. Against `main` the rule is subset rather than exact match: a finding must
still be declared, but a declared finding stops firing there as soon as it
merges, so requiring the whole declaration would fail every later pull request.

After the release is tagged, delete the file or replace it with a declaration
naming its own version and review.

## Pull Request Flow

1. Update the `.proto` sources.
2. Run Buf lint and build locally.
3. Describe compatibility and consumer impact in the pull request.
4. Merge only after the descriptor build passes and the breaking-change check
   either reports nothing or matches a committed reviewed-breaking declaration.
5. Tag a wire release before updating Node, Builder, Cortex, or SDK pins.

During the bootstrap phase, changes must also be reconciled with the matching
Node proto snapshot until the consumer cutover is complete.
