# Changelog

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
