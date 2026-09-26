# Changelog

## v0.3.0

Breaking. Support declarations, capability rows, freshness confirmations, and
activation aggregates now operate at model scope instead of profile-version
scope.

- `ModelCapabilityState` and `ModelSupportState` are keyed by operator and
  model. Declaring support once covers the model's current and future profile
  versions, while task admission continues to bind the selected profile.
- Model state owns the active supporter count, active support stake, effective
  minimum stake, and pending minimum-stake transition. Profile state no longer
  carries support-derived aggregates.
- Daily confirmations commit to a canonical model list under
  `TRUEOPEN_SUPPORT_MODELS_V1`; the former profile-list domain is retired.
- A bounded recheck cursor and explicit suspension reasons make minimum-stake,
  jail, and bond transitions deterministic without scanning all support rows.
- Query, event, genesis, parameter, registry, and cross-language fixture
  surfaces move together so consumers cannot mix profile-scoped and
  model-scoped support semantics.
- Stored service-key responsibilities now carry raw Hash32 session and task
  identifiers, slash receipts use the protocol's uint32 effect index, and
  Builder parameters publish a 128-byte Builder-set ID bound.

Consumers must regenerate from this release and start from fresh genesis state.
The reviewed-breaking declaration is scoped to `v0.3.0` against `v0.2.2`.

## v0.2.2

Additive. Two enum values, one field and two vector entries arrive; no existing
field number, message name or digest changes.

- ADR-0027 makes the Worker-signed Fin the authoritative source of
  `finish_reason`. Three things follow from that, and they ship together
  because any one of them alone leaves the contract inconsistent.

  `task.v1.FinishReasonV1` gains `USER_STOP = 5` and `STOP_TOKEN = 6`.

  `USER_STOP` is what makes a user-stopped task a successful termination
  rather than an abandonment: the Worker signs a Fin carrying it and then
  signs the receipt, so a stopped task is indistinguishable in shape from any
  other completed one, and "no Fin" stays reserved for a Worker that failed or
  gave up, which produces no receipt either. Unlike every other value it
  cannot be checked -- the stop signal arrives off chain -- so it is accepted
  as a Worker assertion, as `MAX_OUTPUT_DURATION` already is.

  `STOP_TOKEN` is separate from `STOP_SEQUENCE` because an order may carry
  both stop strings and stop token ids, and which of the two ended the
  generation is a different fact. It is checkable: the last token of T belongs
  to the order's `stop_token_ids`.

- `nexus.v1.TaskDataObjectMetadataV1` gains `optional OutputFinV1 fin = 7`.

  `finish_reason` previously existed only on the subscription's terminal
  frame, so a non-streaming fetch returned text with no way to tell "the model
  finished" from "the budget cut it off". Whether a fact was obtainable
  depended on which retrieval path the caller chose, and retrieval is meant to
  be a transport detail. The field carries the Worker's original signed frame,
  byte-identical to the one the Builder replays, so the caller verifies it
  against the Worker's service key and compares `output_mmr_root` with the
  receipt rather than trusting the Builder.

  Present only for `OUTPUT` objects that have reached `STORED`. This release
  makes the field exist; populating it on `GetTaskDataMetadata(OUTPUT)` is
  Nexus's side of the ADR.

- `registry/v1/domains.json` corrects the `TRUEOPEN_OUTPUT_FIN_V1` entry.

  `origin` repoints from this repository to ADR-0027, and two statements the
  ADR makes false are removed: that `finish_reason` does not enter
  `TaskDataObjectMetadataV1` -- the MMR half of that claim still holds and is
  kept -- and that cancellation produces no `OutputFinV1`. The closed set
  becomes 1..6.

- `testdata/v1/task/output_mmr_v1.json` opens to the two new values.

  Without this the release would have shipped a contradiction: the vectors
  listed `5` under `rejected_finish_reason_values` as "unknown enum values
  fail closed" while the enum now defines 5 as `USER_STOP`, so a consumer
  implementing against the vectors would have rejected a legal Fin. The
  unknown-value sentinel moves to `7`, the first value above the closed set.

  The two new digests are derived rather than authored. `H_FIELDS_V1` hashes
  its preimage with a plain SHA-256, and `finish_reason` is the trailing
  `uint32_be` of the published `eos_token_preimage_hex`; substituting that
  field reproduces all four existing digests exactly, which is what
  establishes the derivation before it is used for 5 and 6.

  Nothing in this repository reads `accepted_finish_reasons` or
  `rejected_finish_reason_values`, and `verify-fixtures` only recomputes
  objects carrying `preimage_hex`, so no gate could have caught the
  contradiction. The enum and its vectors have no automated consistency check
  between them.

Consumers extending the closed set should note that it is a closed set by
design: `registry/v1` requires unknown values to fail closed before digest
verification, so a consumer that validates `finish_reason` rejects 5 and 6
until it regenerates against this release. On Node that check decides
transaction validity, which makes widening it a coordinated upgrade rather
than a redeploy.

## v0.2.1

Additive. A new proto package arrives **withheld**, so the release makes no
compatibility promise about it and no existing package changes.

- `cortex.v1` moves here from `TrueOpen/cortex`: `ChatInferInput` (the request
  body an SDK constructs), `ChatCompletionOutput`, and the
  `ModelManagementService` Cortex/model-service boundary. `go_package` now
  points at `github.com/TrueOpen/wire/gen/cortex/v1`, matching every sibling.

  The reason to move it is that two repositories were reading one schema, and
  the second copy is the one that drifts. `ChatInferInput` in particular is
  constructed by the SDK and parsed by Cortex.

  It is **withheld, not released**. Its fields are not frozen: ADR-0022 is still
  open, and its back-write matrix assigns Cortex further changes to
  `chat_input` — an `output_decoding` block, a `tool_calling` block, and
  `manifest_version` 3. Releasing it now would mean breaking it next. Move it to
  `released` once ADR-0022 is adopted and those fields have landed.

  Documentation comments were added to 47 messages, RPCs and the service to
  satisfy this repository's `COMMENTS` lint rule, which the originating
  repository did not enforce. No field number, name or type changed in the move.

## v0.2.0

Reviewed breaking change. One field gains explicit presence; no field number,
message name or wire encoding changes.

- `nexus.v1.SubscribeOutputRequest.resume_after_seq` becomes `optional`.

  Under proto3 implicit presence, `0` and "unset" are the same bytes, and
  `seq = 0` is a legal first chunk. So "nothing received yet" and "received
  chunk 0 and nothing more" collide, and a subscriber that reconnects right
  after verifying the first chunk necessarily receives it a second time. Only
  the value `0` is ambiguous; every `n > 0` resumes exactly.

  The distinction was already needed and already faked. Nexus holds the resume
  point as `*uint64` and folds `0` back to nil at the boundary, with a comment
  explaining why it has to. `OutputStreamProgressV1.last_seq`, in this same
  file, already carries explicit presence for exactly this meaning -- two
  identical semantics with two different shapes.

  On the wire this is additive: field number 4, type `uint64` and the encoding
  of every value are unchanged, and a client that omits the field still means
  "replay from the beginning". buf classifies it as `FIELD_SAME_CARDINALITY`
  because the generated API changes -- a pointer in Go, an optional in
  TypeScript -- so it ships as a reviewed break, declared in
  `release/reviewed-breaking.json` rather than by loosening the gate.

## v0.1.1

Fixture repair. No protobuf change: the descriptor image, every field number and
every message name are identical to v0.1.0.

- Recompute the fixture digests that were carried over from the pre-rename
  vectors. A domain literal is hashed into its own preimage, so renaming the
  domains moved every digest derived from them. The v0.1.0 vectors recomputed
  the digests that have a top-level entry but kept the ones nested inside a
  frame, which then propagated into every digest computed from them.
  - `shared/framing_v1.json`: 11 MERKLE_ROOT_V1 roots and the secp256k1
    signature vectors.
  - `shared/params_v1.json`, `shared/query_page_v1.json`: replay rows that
    repeated the base digest and therefore pinned nothing.
  - `hub/candidate_pool_v1.json`: a nested slot binding, and the member set,
    pool, snapshot id and membership binding derived from it.
  - `hub/model_profile_canonical_v2.json`, `task/generation_params_v1.json`,
    `task/output_chunk_equivocation_v1.json`, `task/result_receipt_v2.json`.
- Align the published query selector set with the protos: drop the vectors for
  `PendingEarnings` and `RewardEligibleTasks`, which no proto declares, and
  publish the missing pair for `TaskGasReimbursements`, which they do.
- Restore the producer bindings dropped from eight hub vectors and correct four
  task ones that named helpers no consumer has.
- Restore `limits.max_output_tokens` in the generation params fixture and
  reconcile the two spellings of the nested metric summary field.
- Drop the superseded term-based builder set vector.
- Extend `tools/verify-fixtures` so this class of defect cannot be published
  again: it now recomputes MERKLE_ROOT_V1 and MMR_ROOT_V1 roots, which publish
  leaves and a root but no preimage and so were never checked, and it rejects a
  tamper or replay row whose digest equals the base digest.

## v0.1.0

- Initial TrueOpen wire protocol release.
- Publish neutral protobuf packages for bus, hub, nexus, shared, and task contracts.
- Publish canonical registries and cross-language compatibility fixtures.
