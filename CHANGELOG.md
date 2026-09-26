# Changelog

## v0.3.0

Breaking. This release freezes the contract a fresh genesis starts from.
Consumers must regenerate from it and start from fresh genesis state; no stored
state is migrated. The reviewed-breaking declaration is scoped to `v0.3.0`
against `v0.2.2`.

### Model identity, source and parsers

- `model_id` is a Hash32 everywhere, derived as
  `H_FIELDS_V1("TRUEOPEN_MODEL_ID_V1", chain_id, provider, repo_id,
  proposer_address)`. The Keeper recomputes it on every registration, so a
  model is bound to its source and its registrant, and a different repository
  or owner is a different model. Every `model_id` field is `bytes` with Hash32
  REST encoding.
- `ModelState` gains `provider` and `repo_id`, written once when the model is
  created. `ProfileState` gains `source` (`ProfileSourceRefV1`),
  `tool_call_parser` and `reasoning_parser`.
- `ModelProfileProjection` gains `source` (`SourceRefV1`, field 20),
  `tool_call_parser` and `reasoning_parser` (`ParserRefV1`, fields 21 and 22).
  Registration moves to `TRUEOPEN_MODEL_CHAIN_PROJECTION_V3`,
  `TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3` and `TRUEOPEN_MODEL_MANIFEST_V4`.
- `HubParamsV2.model` (field 16, `ModelParamsV1`) holds the governed
  tool-call and reasoning parser allowlists and the byte caps for source and
  parser strings.
- The EIP-712 order domain moves to version `"3"`, and `TaskOrder.modelId` is
  `bytes32`: the Hash32 itself rather than the keccak of a string.

### Model-scoped support

- `ModelCapabilityState` and `ModelSupportState` are keyed by operator and
  model. Declaring support once covers the model's current and future profile
  versions, while task admission continues to bind the selected profile.
- Model state owns the active supporter count, active support stake, effective
  minimum stake, and pending minimum-stake transition. Profile state no longer
  carries support-derived aggregates, and `ProfileStatusSource` reserves the
  retired `AUTO_SUPPORT` value.
- Daily confirmations commit to a canonical model list under
  `TRUEOPEN_SUPPORT_MODELS_V1`, carrying each model ID as 32 raw bytes in
  strictly ascending order; the former profile-list domain is retired.
- Epoch summaries retain unique model identifiers in raw Hash32 byte order;
  profile versions and composite model/profile strings are invalid. A
  committed truncation flag distinguishes bounded omission from repetition,
  and the query exposes only the complete immutable receipt.
- A bounded recheck cursor and explicit suspension reasons make minimum-stake,
  jail, and bond transitions deterministic without scanning all support rows.
  `ServiceParamsV1.min_stake_grace_period_blocks` (field 22) sets the grace
  period for newly scheduled transitions.
- `ProfileCapabilityState`, `SupportDeactivateCursorState`, `ProfileKeyV1` and
  the `ProfileCapability` query are removed.

### Two-level Worker evidence and V3 receipts

- Worker evidence splits in two. `WORKER_TOKEN_OPENING` (4, new) commits to
  the input and generated token ids and `finish_reason` under
  `TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1`. `WORKER_VALUE_OPENING` (1) commits to
  the Merkle root of the Worker's per-position values under
  `TRUEOPEN_WORKER_VALUE_COMMITMENT_V3`. Trace and checkpoint artifacts are
  gone.
- `InferReceiptV3` carries exactly those two commitments, sorted by enum value,
  under `TRUEOPEN_INFER_RECEIPT_V3`.
- A Verifier now commits to its own values: `TRUEOPEN_RESULT_COMMITMENT_V3`
  binds `verifier_value_root` and the salt instead of `result_payload_hash`,
  so the commit can be locked before the Worker's values are readable.
  `ResultReceiptV3` adds `verifier_value_root` and `metric_leaf_count`, is
  signed under `TRUEOPEN_RESULT_V3`, and reserves field 19. The payload digest
  remains the reveal's integrity check under
  `TRUEOPEN_VERIFIER_RESULT_PAYLOAD_V2`.
- Value leaf and root domains are added for both sides, together with
  `TRUEOPEN_PREFILL_VERIFIER_TOPK_V1`; the metric leaf and root move to V3.
- `InferReceiptState`, `ResultReceiptState`, `CommitState` and `TaskCoreState`
  store the new receipt and order fields. `EventResultAccepted` carries
  `verifier_value_root` in field 7, and field 6 (`result_payload_hash`) is
  reserved.
- `TaskDataObjectRefV1` gains `evidence_kind`, so the two Worker bundles of one
  round are distinct objects, and `FinalizeTaskResultRequest` finalizes each by
  kind. The five task-data body domains and
  `TRUEOPEN_BUILDER_STORAGE_CONFIRMATION` move to `_V2`.
- `MsgSubmitVerifierValueEvidence` and `VerifierValueEvidenceKindV1` are
  registered ahead of activation, and `MsgReportDataUnavailable` gains
  `evidence_kind` and `reason`.

### Reserved encryption slots

- `TaskOrderV3` (28 fields) replaces `TaskOrderV2`: `payload_mode`
  (`PayloadModeV1`), `input_key_commitment` and `user_recipient_pubkey` enter
  the task hash under `TRUEOPEN_TASK_ORDER_V3`.
- Both handraises gain `recipient_pubkey`; `InferReceiptV3` fields 15 to 18 and
  `ResultReceiptV3` field 18 hold key commitments.
- `OutputStreamHeaderV2` adds the attempt, stream instance and key fields and
  is Worker-signed under `TRUEOPEN_OUTPUT_STREAM_HEADER_V1`.
- `encryption_activation_height` is 0, so `PLAINTEXT` is the only accepted
  mode and every reserved slot must be empty.

### Representation and parameters

- Stored service-key responsibilities now carry raw Hash32 session and task
  identifiers, slash receipts use the protocol's uint32 effect index, and
  Builder parameters publish a 128-byte Builder-set ID bound.
- Builder-set mode is now a closed enum, and all Task reference counters use
  the common uint32 representation.
- `min_output_stream_frame_bytes` is 256.

Query, event, genesis, parameter, registry, and cross-language fixture surfaces
move together, so consumers cannot mix the old and new semantics.

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
