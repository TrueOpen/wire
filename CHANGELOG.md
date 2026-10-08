# Changelog

## Unreleased

### EIP-712 domain chainId chosen by the signer; `evm_chain_id` removed (breaking)

Ethereum wallets require the EIP-712 domain `chainId` to equal their active
network, so a domain pinned to a chain parameter forced users onto a TrueOpen
network that runs no EVM. The domain `chainId` of all four domains is now chosen
by the signer and carried next to the signature (TrueOpen/wire#42). This is a
pre-genesis break with no transition window: signers and verifiers of the old
and new rules do not interoperate, and node, Nexus, the SDK and Cortex must move
together. The proto change is declared in `release/reviewed-breaking.json` for
v0.5.0 against v0.4.0.

- **New carried fields**, each the domain `chainId` of its signature, in
  `1..MaxInt64` (0 is `NEXUS_INGRESS_MALFORMED` at the format step):
  `task.v1.SignedOrderV2.signature_chain_id = 4`,
  `nexus.v1.SessionGrantV1.signature_chain_id = 7`,
  `nexus.v1.TaskDataRequestAuthV1.signature_chain_id = 13` (USER only;
  CORTEX_SERVICE must carry 0) and
  `nexus.v1.SDKRequestEnvelopeV2.signature_chain_id = 14`. The transaction
  path keeps the upstream `ExtensionOptionsWeb3Tx.typed_data_chain_id`; only
  its rule changes, from "equals `evm_chain_id`" to `1..MaxInt64`.
- **`hub.v1.Phase0ParamsV1.evm_chain_id` is removed**; field 11 and the name
  are reserved. The `hub_params_v2` commitment in
  `testdata/v1/shared/params_v1.json` is recomputed without it (2265-byte
  preimage, 136 scalars); `task_params_v1` is unchanged.
- **Cross-chain isolation comes only from the `chain_id` string.** The
  verifier still takes `Tx.chain_id` and every typed `chainId` from its own
  chain; the domain `chainId` isolates nothing. Domain names, versions and
  typed structs are unchanged, so every existing digest computed with
  `424242` as the domain `chainId` is still the digest of the same message
  carrying `signature_chain_id = 424242`.
- **Identity, replay and retry bindings exclude signatures.** No identity,
  replay, dedup or OpenTask exact-retry binding may include the signature or
  `signature_chain_id`. An OpenTask retry under the same `idempotency_key`
  compares `task_hash`, `input_hash` and `input_size_bytes` only; a retry
  re-signed under another network is verified on its own and the stored
  `SignedOrderV2` is kept.
- **OpenTask may be signed by a session key.** OpenTask joins the
  session-allowed set; the grant user must also equal the `SignedOrderV2`
  user, otherwise `SDK_AUTH_SESSION_GRANT_INVALID`. The order itself is still
  signed by the wallet.
- `testdata/v1/shared/account_signing_v1.json`: every typed section, envelope
  and grant transport publishes its carried `signature_chain_id`, and
  `tools/verify-vector-consistency` requires it to equal the domain `chainId`
  the digest was built with. New sections and rows:
  `sdk_request_open_task_session` (session-signed OpenTask, accepted);
  `sdk_request_tampered_signature_chain_id` and
  `task_data_request_tampered_signature_chain_id` (renamed from the
  `other_evm_chain_id` rows); `sdk_request_signed_under_other_signature_chain_id`;
  wallet-network `signature_chain_id = 1` acceptances for the SDK request,
  Task data request, task order and session grant;
  `signature_chain_id_zero`, `signature_chain_id_above_max_int64`,
  `session_grant_signature_chain_id_zero`,
  `cortex_service_signature_chain_id_nonzero` and
  `open_task_session_grant_user_not_order_user` (rejections). The
  `open_task_with_session_grant` rejection is removed. On
  `msg_create_session_transaction`, `evm_chain_id` is renamed
  `typed_data_chain_id`.
- `bus` strict decoding pins `SignedOrderV2` field 4.

## v0.4.0

**Reviewed breaking change, pre-genesis.** User request signing moves to EIP-712 with session grants (see the breaking section below); Nexus and the SDK must upgrade together. Also includes the release-notes and SDK-coverage vectors merged after v0.3.3.

- `SubmitOrder`, `FetchOutputRef` and `RefreshCredential` are retired: once Nexus switches to
  `SDKRequestEnvelopeV2`, each always returns Unimplemented with
  `NEXUS_INGRESS_METHOD_RETIRED`, before parsing the request or verifying any
  signature. No body domain is defined for them. Comment-only change.
- User request verification rules are pinned; comment and fixture-note
  change only, with no field, domain, digest or signature changed:
  - The verifier rebuilds the `SDKRequest` and `TaskDataRequest` digests with
    its own `chain_id` and `evm_chain_id`, never the request's. A request
    signed for another chain fails at recovery with
    `SDK_AUTH_INVALID_SIGNATURE` (as `sdk_request_other_chain_id` shows), not
    at the format step. The replay key uses the verifier's own `chain_id`.
  - A wallet-signed USER `TaskDataRequestAuthV1` gets the same account check
    as `SDKRequestEnvelopeV2`: the recovered key must equal the account's
    stored `eth_secp256k1` key, otherwise `DATA_ACCESS_INVALID_SIGNATURE`.
    The service step then checks, in order, `builder_operator_address`
    (another Builder is `DATA_ACCESS_DENIED`), the
    `max_service_material_expiry_blocks` expiry window (`NEXUS_DATA_EXPIRED`,
    distinct from the retention `DATA_EXPIRED`), replay and the Task duty.
  - The envelope `chain_id` field (and the Task data request `chain_id`)
    must equal the verifier's own `chain_id`. A mismatch is rejected at the
    signature step with `SDK_AUTH_INVALID_SIGNATURE` or
    `DATA_ACCESS_INVALID_SIGNATURE`, never as `NEXUS_INGRESS_MALFORMED`. A
    session grant's `chain_id` is compared with the verifier's own `chain_id`.
  - OpenTask accepts only a chain-height expiry; a Unix millisecond value
    (10^12 or more) is `NEXUS_INGRESS_MALFORMED` at the format step. The
    height must satisfy
    `current_height <= expiry <= current_height + request_ttl_blocks`
    (Builder configuration, default 20), otherwise `SDK_AUTH_EXPIRED`; an
    unavailable chain height is a rejection.
  - `SDKRequestEnvelopeV2.signer_address` and the OpenTask `user_address`
    must be canonical lowercase Bech32 with the `trueopen` prefix, decoding
    to exactly 20 bytes, otherwise `NEXUS_INGRESS_MALFORMED` at the format
    step. The `TRUEOPEN_SDK_BODY_OPEN_TASK_V1` registry note says so.
  - `testdata/v1/shared/account_signing_v1.json` notes now state the timing
    the expected results assume: `max_session_grant_blocks` 400,
    `max_service_material_expiry_blocks` 604800 (any value of 800 or more
    gives the same results), `request_ttl_blocks` 20, current height 1200
    for the session rows, and 1000 for the OpenTask `sdk_request` row.

### User request signing: EIP-712 with session grants (breaking)

User requests to Builder Ingress and USER Task data requests are now signed as
EIP-712 typed data that a browser wallet can sign, a short-lived session key can
sign the read and delivery-progress requests after one wallet prompt, and every
request body digest is a registered `H_FIELDS_V1` domain. This is a
pre-genesis revision: digests and signatures computed under earlier releases
for the domains and messages named below are superseded, and every
implementation must move to this release. The proto change is a reviewed
break, declared in `release/reviewed-breaking.json` for v0.4.0 against
v0.3.3.

- **`SDKRequestEnvelopeV1` is renamed `SDKRequestEnvelopeV2`** (`nexus.v1`).
  Field numbers are unchanged. `request_domain` is now
  `TRUEOPEN_SDK_REQUEST_V2`; it is checked and used in the replay key but not
  signed. `signature` is now 65 bytes `R||S||V` (V in {27, 28}, low S) over
  the EIP-712 `SDKRequest` digest, and the verifier recovers the signer from
  it. `signer_pubkey` (field 12) is deprecated and ignored: no address is
  derived from or checked against it. The old signature - SHA-256 over the
  length-prefixed `TRUEOPEN_SDK_REQUEST_V1` field list, 64 bytes `r||s`, with
  a caller-supplied public key - is removed. The nine request messages that
  carry the envelope change type accordingly: `OpenTaskHeader`,
  `ConfirmOpenTaskRequest`, `SubscribeOutputRequest`, `AckOutputRequest`,
  `GetTaskEventsRequest`, `PrepareChallengeRequest`, and the deprecated
  `SubmitOrderRequest`, `FetchOutputRefRequest` and
  `RefreshCredentialRequest`.
- **New EIP-712 domain `"TrueOpen SDK Request"` version `"1"`** (chainId the
  EVM chain ID) with two primary types:
  `SDKRequest(string chainId,string method,string endpoint,bytes32 sessionId,bytes32 taskId,bytes32 requestNonce,uint64 expiryHeightOrTime,bytes32 bodyDigest,bytes32 sessionGrantHash)`
  and
  `SessionGrant(string chainId,string user,address sessionKey,uint64 expiryHeight,bytes32 grantNonce)`.
  `sessionGrantHash` is 32 zero bytes without a grant and
  `hashStruct(SessionGrant)` with one; the verifier derives it. `method` is
  the bare method name and `endpoint` the full procedure
  `/nexus.v1.IngressAPI/<Method>`, whose `<Method>` must equal `method`.
  `session_id` and `task_id` are decoded strictly from 64-character lowercase
  hex without `0x`; `request_nonce` is exactly 32 bytes; an expiry of 0 or
  below is rejected before projection; an OpenTask `task_id` must equal
  `TRUEOPEN_TASK_ID_V1(session_id, order_sequence)`. A SessionGrant is always
  signed under this domain, including when a Task data request carries it.
- **Session grant.** New message `SessionGrantV1` (`chain_id`, `user`,
  `session_key` raw 20 bytes, `expiry_height`, `grant_nonce` 32 bytes,
  `user_signature` 65 bytes) and the optional field
  `SDKRequestEnvelopeV2.session_grant` (13). A grant is valid while
  `current_height <= expiry_height <= current_height + max_session_grant_blocks`;
  there is no revocation. A session key may sign only SubscribeOutput,
  AckOutput, GetTaskEvents and PrepareChallenge, and GetTaskDataMetadata and
  FetchTaskData of an OUTPUT object. OpenTask and every other request must be
  signed by the wallet and are rejected with a grant. Grant failures have
  their own codes: `SDK_AUTH_SESSION_GRANT_INVALID`,
  `SDK_AUTH_SESSION_GRANT_EXPIRED` and `SDK_AUTH_SESSION_METHOD_NOT_ALLOWED`,
  and the `DATA_ACCESS_SESSION_*` counterparts on the Task data path. The
  verifier runs format, session method set, grant, request signature, then
  expiry and replay, stopping at the first failure; a wrong derived grant hash
  is a request signature failure (`SDK_AUTH_INVALID_SIGNATURE` or
  `DATA_ACCESS_INVALID_SIGNATURE`).
  `max_session_grant_blocks` is off-chain configuration that every Task
  Builder must set to the same value.
- **TaskDataRequest EIP-712 domain version `"2"`.** The USER path of
  `TaskDataRequestAuthV1` signs
  `TaskDataRequest(uint32 schemaVersion,string chainId,string builderOperatorAddress,string rpcMethod,bytes32 bodyDigest,uint32 requesterKind,string requesterAddress,uint64 serviceAuthorizationNonce,bytes32 requestNonce,uint64 expiryHeight,bytes32 sessionGrantHash)`
  under `"TrueOpen Task Data Request"` version `"2"`; version `"1"`, without
  `sessionGrantHash`, is no longer accepted. `TaskDataRequestAuthV1` gains
  field 12 `session_grant` (USER only). The CORTEX_SERVICE path and
  `TRUEOPEN_TASK_DATA_REQUEST_V1` are unchanged.
- **Five new body domains**, registered in `registry/v1/domains.json` as
  `H_FIELDS_V1` rows and replacing unregistered bare SHA-256 body digests:
  `TRUEOPEN_SDK_BODY_OPEN_TASK_V1`, `TRUEOPEN_SDK_BODY_SUBSCRIBE_OUTPUT_V1`,
  `TRUEOPEN_SDK_BODY_ACK_OUTPUT_V1`, `TRUEOPEN_SDK_BODY_GET_TASK_EVENTS_V1`
  and `TRUEOPEN_SDK_BODY_PREPARE_CHALLENGE_V1`. `tools/verify-registry` now
  requires all five.
- **OpenTask has no outer order signature.** `OpenTaskHeader.signature` and
  `signature_scheme` are deprecated, must be empty and do not enter the body
  digest. The order is authorized only by the SignedOrder EIP-712 user
  signature; the request envelope must be wallet-signed and recover to the
  order user, whose account must already hold its public key on chain. The
  OpenTask body takes `task_hash` recomputed from the order, never from the
  caller. `payload_ref` is not in the body: it must equal
  `"nexus://sha256/" || lowercase_hex(input_hash)`, a transport check only.
- **ConfirmOpenTask is not callable in V1.** Its body domain is not frozen, so
  the Builder returns FailedPrecondition with
  `NEXUS_INGRESS_CONTRACT_NOT_FROZEN`; it carries the V2 envelope type only
  so that the message stays defined.
- **Obsolete vector.** `account_signing_v1.json` `task_data_request` is now
  the version 2 vector. The version 1 vector is kept, unchanged, as
  `task_data_request_v1_obsolete` with `expect: reject`.
- **Vectors.** `account_signing_v1.json` gains `sdk_request` (OpenTask,
  wallet signed), `sdk_request_session` (SubscribeOutput, session-key signed),
  `session_grant`, `task_data_request_session` (GetTaskDataMetadata of an
  OUTPUT object under a grant), the `session_key` and `wrong_key` test keys,
  and `request_auth_negative_cases`: wrong chain ID and EVM chain ID, domain
  version 1, wrong signing key, `sessionGrantHash` mismatch in both
  directions, expired and out-of-window grants with the inclusive edges,
  a grant for another chain, OpenTask and UploadTaskResultObject with a
  grant, ConfirmOpenTask, a tampered body digest, zero and negative expiry,
  uppercase and `0x`-prefixed ids, a 16-byte nonce, a method/endpoint
  mismatch and an OpenTask `task_id` that is not derived from the order. New `testdata/v1/task/sdk_request_body_v1.json` has one base vector
  per body domain with tamper, replay and cross-domain rows.
- **Tools.** New `tools/internal/eip712`, a dependency-free Keccak-256,
  secp256k1 (RFC 6979, recovery) and EIP-712 implementation, checked against
  the Node-produced order signature. `tools/verify-vector-consistency` now
  recomputes every EIP-712 value (key derivations, domain separators, type
  hashes, hash_struct, signing digests, exact signatures, recovered
  addresses, the Tx vector from its canonical amino JSON, and every negative
  request row) and supports cross-domain replay rows.

Consumers that byte-compare fixture copies must refresh
`shared/account_signing_v1.json` and add `task/sdk_request_body_v1.json`.

### Vectors and notes

The items below add vectors and notes only: no preimage, framing or proto
field change. The proto edits they made are comments only.

- Generation parameter ranges. `DecodingParamsV1` comments now state the
  inclusive ranges the Keeper enforces: `temperature_milli` 0..2000,
  `top_p_ppm` 1..1000000, `top_k` 0..`generation.top_k_max` (default 1000),
  both penalties -2000..2000, `repetition_penalty_ppm` 100000..2000000. The
  chain fills no default. New `testdata/v1/task/generation_params_ranges_v1.json`
  has min, max, min-1 and max+1 for each field, with the accepted payloads and
  digests. The order projection does not bound `top_k`; only the generation
  parameter digest does.
- Order economics. The `TaskOrderV3` comment states how `order_value` is
  derived (`floor(max_output_tokens * price_bid / 1e6)` plus
  `floor(worker_max * verify_ratio_bps / 1e4)`, u64 with a 128-bit
  intermediate) and every rejection. New
  `testdata/v1/task/order_economics_v1.json` covers rounding and overflow.
- Fee denomination. The order EIP-712 `feeDenom`, `ProfileState.min_stake` and
  `registration_fee_paid`, and the projection's `min_stake` and
  `registration_fee` Coins are documented as the chain `business_denom`, with
  amounts only in state. `account_signing_v1.json` gains `fee_denom_source`
  notes.
- `account_signing_v1.json` gains `direct_sign_mode_transaction`: a
  SIGN_MODE_DIRECT transaction with an eth_secp256k1 key, from SignDoc bytes
  through keccak256 to the 64-byte signature, with the public key type URL.
- `task_order_v3.json`: every mutation row gains an `edit` that states its
  change machine-readably. Digests are unchanged.
  `tools/verify-vector-consistency` now recomputes every mutation row that has
  one.
- End-to-end vectors. New `testdata/v1/hub/model_registration_chain_v1.json`
  chains the golden manifest digest through the projection to the
  registration digest, and adds projection-only vectors with non-empty
  `ParserRefV1` values. New `testdata/v1/task/task_order_eip712_v1.json` links
  each accepted `task_order_v3.json` order to its EIP-712 signing digest.
- `manifest_uri_v1.json` gains IPv6 zero-run tie-break, IPv4-mapped and
  dotted-tail IPv6, label and port cases.
- New `testdata/v1/shared/rest_json_shapes_v1.json` shows how the Node REST
  gateway renders QueryTask (active and terminal), QueryProfile, QueryCortexNode
  and both Params responses: snake_case names, Hash32 as lowercase hex (omitted
  when unset), other bytes as Base64, 64-bit integers as strings.
- `testdata/README.md` and the fixture manifest notes list the three fixture
  values above 2^53 that are bare JSON numbers. The values are unchanged.

Consumers that byte-compare fixture copies must refresh
`hub/manifest_uri_v1.json`, `shared/account_signing_v1.json` and
`task/task_order_v3.json`.

- Release pages now carry only their own version's CHANGELOG section
  (`release/notes.sh`); the release job fails when the tag has no section.

## v0.3.3

**Fixture and notes correction only; no preimage, framing
or proto change.** Every base digest is unchanged. What changes is rows,
counts, names and notes that described the vectors wrongly, plus one added
vector and a CI check that would have caught the rest.

- `testdata/v1/shared/query_page_v1.json`: the `cross_chain` replay row of
  `query_selector_v1_hub_freeze_signals` still carried the digest of the
  preimage from before `model_id` became raw 32 bytes. Recomputed with the
  current framing: `163429a0…` → `efcd3bed…`. Every other tamper and replay row
  in the file recomputes to its published digest.
- `testdata/v1/shared/params_v1.json`: `hub_params_v2` `leaf_accounting` is
  corrected from 138 scalars / 34 submessages / 4 repeated to 137 / 32 / 4. The
  counting rule, which `task_params_v1` already followed, is now a file note:
  within the params frame, a non-frame field is a scalar, a frame whose first
  child is `element_count` is one repeated field (and that `element_count` is
  not a scalar), and any other frame below the root is a submessage. Node
  byte-compares this file, so its copy must be refreshed.
- `testdata/v1/shared/shared_domains_v1.json`: the `TRUEOPEN_BATCH_RESULT_V1`
  vector's `contract_section` now reads "Public wire domain
  TRUEOPEN_BATCH_RESULT_V1", matching `registry/v1/domains.json`.
- `source_commit` in `registry/v1/domains.json`, `registry/v1/framing.json` and
  `testdata/v1/manifest.json` is documented rather than changed. It names a
  commit of `source_repository` (TrueOpen/node), not of this repository, and
  pins only the registry rows without an `origin` and the `origin: node`
  fixtures. It is not reachable in the public history of that repository, so it
  is provenance only; tooling checks its form and that the two registries
  agree. `README.md` and the three JSON schemas now say so. No value was
  changed, because no public commit is the one those bytes were copied from.
- `registry/v1/domains.json`: the `TRUEOPEN_COMMIT_V1` note named
  `TRUEOPEN_RESULT_COMMITMENT_V1` as the source of `commit_hash`; the proto and
  the registry both define it as `TRUEOPEN_RESULT_COMMITMENT_V3`. The note is
  corrected.
- `testdata/v1/task/task_data_auth_v1.json`: the four `evidence_kind` mutation
  rows changed the kind by +1, which lands on a kind that is illegal for that
  object or request (a Verifier evidence object carrying
  `SETTLEMENT_ROOT_OPENING`, a result finalize selecting
  `VERIFIER_VALUE_OPENING`, an `OUTPUT` reference carrying
  `WORKER_VALUE_OPENING`). They were published as `digest_changes`; they are now
  `expect: reject_before_hash` rows with no digest and a `reason`, the reject
  convention `output_chunk_equivocation_v1.json` already uses. A file note
  explains the two row kinds.
- Canonical JSON notes: `canonical_json_v1.json` said Hash32 is written as 64
  lowercase hex, but the generation-parameter payloads write `model_id` as `0x`
  followed by 64 lowercase hex. The note now states the exception, and the
  `TRUEOPEN_TASK_GENERATION_PARAMS_V1` registry row gains a note saying the
  same. No vector bytes changed.
- Duplicate vector names are made unique by output position:
  `integrated_metric_leaf_position_{0,1,2}` in `result_metric_v3.json`,
  `verifier_topk_set_position_{0,1,2}` and
  `verifier_value_leaf_position_{0,1,2}` in `verifier_value_leaf_v1.json`, and
  `worker_value_leaf_position_{0,1,2}` in `worker_value_leaf_v1.json`. A
  consumer that selected these by the old name (or by name plus occurrence
  index) must switch to the new names or select by domain.
- `testdata/v1/task/result_receipt_v3.json`: new vector
  `metric_summary_v1_zero_leaves_optional_ratios_disabled`, a result with no
  metric leaves and both optional ratios (top-K Jaccard and union JS) disabled.
  Every count and number is 0, both optional ratios are absent, and the sample
  is judged PASS. It is computed by the same MetricSummaryV1 rule
  `verify-fixtures` applies to `metric_summary_v1_zero_leaves`, and that test
  now pins the comparison flags of each no-comparable-leaf vector.
- `tools/verify-vector-consistency` (new CI step in the `contract` job): it
  recomputes every `leaf_accounting` from its field tree, recomputes every base
  vector, tamper row and replay row from domain and fields and compares the
  result with the published digest, and requires vector names to be unique
  within a file. Run against the `v0.3.2` fixtures it reports exactly the stale
  replay digest, the wrong `leaf_accounting` and the duplicate names above.
- `testdata/v1/manifest.json`: sizes and SHA-256 refreshed for the nine changed
  fixtures.
- Removed references to non-public material from comments, notes and fixture
  prose; no semantic change.
- Release process (committed earlier on this branch): `release/README.md`,
  `CONTRIBUTING.md` and `VERSIONING.md` now require Node, Cortex and SDK to be
  verified against the candidate wire commit before the tag is cut, and a wire
  tag to exist before any consumer pin update merges.


## v0.3.2

**Fixture-only correction, digest-changing, pre-genesis.** No proto change.

- `testdata/v1/shared/params_v1.json`: `hub_params_v2` omitted
  `SupportParamsV1.max_model_support_deactivate_items_per_block` (field 14),
  which `v0.3.0` added to the proto, so `v0.3.0` and `v0.3.1` published a
  `TRUEOPEN_HUB_PARAMS_V2` digest computed over a message without that field.
  The field is added at its position with value 32; digest `62cc263e…` →
  `56c5d2e3…`, with the replay and tamper rows recomputed. Under the "Before
  genesis" policy in `VERSIONING.md`, the `hub_params_v2` digest published by
  `v0.3.0` and `v0.3.1` is superseded and implementations move to `v0.3.2`.
- `tools/verify-params-fixture` (new CI step): every field of every params
  message the parameter vectors encode must appear in the fixture, by name and
  in field-number order, so a params field added to the proto without a
  fixture entry fails CI.

## v0.3.1

**Digest-changing, pre-genesis.** The V3 model projection
gains a field in place, so `TRUEOPEN_MODEL_CHAIN_PROJECTION_V3` and
`TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3` digests change and an implementation
pinned to `v0.3.0` computes different values for the same registration. No chain
runs `v0.3.0`; implementations move to `v0.3.1` together. Proto changes are
additive, so `buf breaking` is clean.

Revised in place under the "Before genesis" policy in `VERSIONING.md`:
`TRUEOPEN_MODEL_CHAIN_PROJECTION_V3` and `TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3`
(through `chain_projection_hash`). Digests computed for these two domains under
`v0.3.0` are superseded; all implementations must use `v0.3.1`.

- `shared/v1/model_profile.proto`: `ModelProfileProjection.manifest_uri`
  (field 23), the registrant-hosted retrieval pointer for the manifest body.
  It enters the projection and registration digests; it is not inside the
  manifest and does not enter `manifest_hash`.
- `hub/v1/model_profile_state.proto`: `ProfileState.manifest_uri` (field 34),
  frozen with the profile version and returned by `Query/Profile`, which
  serves as the manifest-pointer query.
- `hub/v1/params.proto`: `ModelParamsV1.max_manifest_uri_bytes` (field 12,
  2048 in the published parameters).
- `testdata/v1/hub/manifest_uri_v1.json`: accepted and rejected `manifest_uri`
  forms for `https` and `ipfs`, with the strict reading taken where the syntax
  leaves room; `verify-fixtures` runs a reference validator over it.
- `testdata/v1/hub/model_profile_canonical_v3.json`: the projection carries a
  `manifest_uri` whose query contains `&`, written literally, so an encoder
  that HTML-escapes canonical JSON cannot reproduce it; `chain_projection_hash`
  `d9a3cc73…` → `e8bc8a61…`, registration digest `abd16723…` → `6a55016e…`.
- `verify-fixtures` re-encodes canonical JSON with HTML escaping off (it had
  used `json.Marshal`, which escapes `<`, `>` and `&`) and asserts the
  projection payload carries a literal `&`.
- `testdata/v1/shared/params_v1.json`: `hub_params_v2` includes the new cap;
  digest `b40396c3…` → `62cc263e…`, replay and tamper rows recomputed.
- `docs/MANIFEST_RETRIEVAL_V1.md`: fetch order, processing order, downloader
  safety obligations and the test scenarios implementers must cover.
- `release/reviewed-breaking.json` is retired: it authorized the `v0.3.0`
  break against `v0.3.0-rc.2`, and this release has no `buf breaking` findings.

- The release job picks the previous release as its compatibility baseline by
  semantic version, ordering a pre-release before its release; it had picked
  `v0.3.0-rc.2` over `v0.3.0`.

## v0.3.0

- `hub/v1/daily_support.proto`, `hub/v1/params.proto`, `hub/v1/genesis.proto`:
  add `ModelSupportDeactivateCursorState`, a bounded one-way sweep that
  deactivates every `ModelSupportState` row for a model after it transitions
  to FROZEN or DELISTED (`GenesisState` field 105), and its per-block budget
  `SupportParamsV1.max_model_support_deactivate_items_per_block` (field 14),
  independent from the existing recheck-cursor budget. Purely additive.
- `task/v1/infer_receipt.proto`: the byte-exact expansion of
  `TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1` in the comment wrote the list
  elements at the top level and gave the domain as 35 bytes. It now matches
  the published vectors and the encoding every implementation uses: a leading
  `uint32_be(count)` plus one repeated field that carries its own count and the
  length-framed elements; the domain is 38 bytes. Comment only; no encoding or
  vector changes.
- `result_metric_v3.json`: publishes `metric_aggregate_proof_v1`, the v0.3.0
  aggregate proof (`PREFILL_METRIC_AGGREGATE_PROOF_V1`, 504 bytes) of the same
  Verifier result, with `model_id` framed as its raw 32 bytes, like every other
  v0.3.0 encoding of a model ID. Its digest replaces the opaque
  `aggregate_proof_hash` in `result_v3_signing_digest` and the V2 reveal
  payload and the `aggregate_proof` content hash in the Verifier evidence
  manifest (`evidence_bundle_manifest_v1`, still 603 bytes); the manifest's
  bundle hash, the result signing digest and the payload digest are
  recomputed. `verify-fixtures` rebuilds the proof from the published chain and
  checks every link.
- `canonical_json_v1.json`: the Verifier evidence manifest
  (`evidence_bundle_manifest_v1`) named the Worker as `producer_operator` and a
  placeholder `evidence_schema_hash`. It now belongs to the Verifier result it
  is bound to (the Verifier's address, the chain's evidence schema hash); its
  bundle hash, `result_v3_signing_digest` and the V2 reveal payload are
  recomputed, and `verify-fixtures` checks the manifest identity against the
  result.
- `result_receipt_v3.json`: `verify-fixtures` recomputes `metric_summary_v1`
  from the published metric leaves with an integer-only implementation of the
  MetricSummaryV1 rules (half-up mean, nearest-rank percentiles saturating at
  the uint32 maximum, rank-delta rate over comparable leaves, compared counts);
  the published summary already matched, so no digest changes.
- `result_receipt_v3.json`: two standalone summaries pin the case with no
  comparable leaf, every comparison enabled. `metric_summary_v1_zero_leaves`
  (no leaves, a legal zero-token output judged PASS with count 0): every
  numeric field 0, both ratios present(0), all counts 0.
  `metric_summary_v1_worker_values_missing` (three leaves whose Worker values
  are all missing): abs logprob diff mean/p95/p99 4294967295, rank-delta rate
  1000000, top-K Jaccard present(0), union JS present(1000000), compared counts
  0, so it never reads as agreement. When no comparable leaf exists, a
  Verifier-side miss produces no summary (a Verifier execution failure), so it
  has no vector; with comparable leaves, missing positions count in the summary.

## v0.3.0-rc.2

Second pre-release of v0.3.0. Fixture-only corrections to the v0.3.0 vectors,
plus the release job now marks pre-release tags as pre-releases. No proto,
registry or encoding rule changes; `buf breaking` against `v0.3.0-rc.1` is
clean, so the reviewed-breaking declaration that authorized the v0.3.0 break
against `v0.2.2` is retired.

- `result_receipt_v3.json`: `result_v3_signing_digest` and
  `verifier_result_payload_v2` now name the Verifier evidence manifest this
  release publishes (`canonical_json_v1.json`, 603 bytes, `5b56779a…`)
  instead of the retired 556-byte one. `verify-fixtures` now checks that
  link, so the two cannot drift apart again.
- `infer_receipt_v3.json`: adds `infer_receipt_v3_distinct_counts`, in which
  `generated_token_count` and `output_leaf_count` differ. With both at 3,
  an implementation that swapped the two fields reproduced every vector.
- `metric_leaf_v3.json`: adds `metric_leaf_v3_worker_rank_outside_top_k`, a
  finite leaf with `worker_rank` 0, so `effective_rank(0) = required_top_k
  + 1` is pinned; `verify-fixtures` checks `rank_delta` on every finite leaf.
- `output_stream_header_v1.json`: names the service key the header
  signature verifies under.
- Generation-parameter payloads (`canonical_json_v1.json`
  `task_generation_params_v1`, `generation_params_v1.json`) were produced with
  HTML escaping on (`\u003c/s\u003e`); canonical JSON writes `<`, `>` and `&`
  as themselves. Both are regenerated (new digests `b9cc1d8c…` and
  `632e73cf…`), and `verify-fixtures` rejects HTML escapes in these payloads.
  `docs/CANONICAL_ENCODING_V1.md` now states the string escaping rule and that
  signed integers are allowed where the schema declares them.
- The Worker A-level bundle carries `generation_params`, the exact canonical
  generation-parameter bytes, so a Verifier has the parameters it prefills
  under. `evidence_bundle_manifest_worker_token_v1` gains that artifact; the
  A-level `encoded_size_bytes` still counts only the two token-id artifacts.
- The vectors are now consistent end to end: the A-level commitment and both
  `infer_receipt_v3` vectors bind the real generation-parameter digest instead
  of a placeholder, with the commitment list, receipt digests and the V2
  reveal payload recomputed; the Worker evidence confirmations in
  `builder_confirmation_v1.json` name the published commitments, manifest
  lengths and artifact totals. `verify-fixtures` checks each link.
- The Verifier side binds the same parameters: every metric leaf in
  `metric_leaf_v3.json` and `result_metric_v3.json`, and
  `result_v3_signing_digest`, carry the real generation-parameter digest
  instead of a placeholder; the metric roots, the result signing digest and
  the V2 reveal payload are recomputed, and `verify-fixtures` checks the link.

## v0.3.0-rc.1

Pre-release of v0.3.0. Node, Nexus and Cortex implement against this
descriptor; `v0.3.0` final follows once those implementations and a localnet
run confirm it, and any break found first ships as a further `-rc`.

Breaking. This release freezes the contract a fresh genesis starts from.
Consumers must regenerate from it and start from fresh genesis state; no stored
state is migrated. The reviewed-breaking declaration is scoped to
`v0.3.0-rc.1` against `v0.2.2`.

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
- `cortex.v1` (still withheld) follows the split. `InferResponse` returns
  `token_ids_ref` and `position_values_ref`, naming a `TokenIDsV1` and a
  `PositionValuesV1` artifact, in place of `trace_ref` and `checkpoint_ref`;
  `ManagedModelCapability` advertises the matching `supports_*` flags. Verify
  takes token ids only and returns the verifier's own `verifier_values`; the
  comparison against the Worker moves into Cortex, so `MetricSampleV1`,
  `MetricOptionalFP` and `VerifyResponse.metric_samples` are removed. Values
  cross this hop as doubles and are converted to `fp_1e6` in Cortex alone.

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

- The Worker-signed Fin becomes the authoritative source of
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
  Nexus's side of the change.

- `registry/v1/domains.json` corrects the `TRUEOPEN_OUTPUT_FIN_V1` entry.

  `origin` no longer names this repository as the source, and two statements
  the new rule makes false are removed: that `finish_reason` does not enter
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

  It is **withheld, not released**. Its fields are not frozen: an open design decision
  still assigns Cortex further changes to
  `chat_input` — an `output_decoding` block, a `tool_calling` block, and
  `manifest_version` 3. Releasing it now would mean breaking it next. Move it to
  `released` once those fields have landed.

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
