# Phase 1 direct dispatch and session prefunding

This is a coordinated, breaking contract for a fresh genesis. It does not
support replay, migration, old sessions, old parameter commitments or old
message decoders from a retained Phase 0 chain. Publish a reviewed release and
pin its immutable tag and descriptor digest in every consumer before activation.
This document describes the candidate contract; it is not a release announcement.

## Contract coverage

| Area | Source and public behavior |
| --- | --- |
| Standing offers and dispatch | `task/v1/dispatch.proto`: signed standing handraises, admission roots/proofs, per-round rosters, tickets, accept/reject facts and complete records |
| Chain admission and takeover | `msg_dispatch.proto`: independently admitted dispatch/takeover entries, distinct entry identities and bounded per-item results |
| Session funds and authorization | `session.proto`, `msg_session.proto`: initial prefund/Builder binding, deposits, delayed withdrawals/CLOSE, key changes, cancellation and pending takeover |
| Compensation and challenges | Task dispatch state/messages and Hub fault state: retained winner exclusions, rebuttable claims, omission/draw/skip/roster challenges and double-dispatch proofs |
| Historical weight inputs | `hub/v1/dispatch.proto`, `candidate_pool.proto`: epoch snapshot inputs and optional profile-specific membership/weight query |
| Builder operations | `hub/v1/dispatch.proto`, VRF messages: permissionless compensation funding and separate Builder/Validator VRF identities |
| Direct transport | `nexus/v1/dispatch.proto`, `ingress.proto`: typed duplex stream, stream binding/cursors, input retrieval, notices, output resume and complete rosters |
| Output and receipts | `InferReceiptV3`, `OutputStreamHeaderV2`, subscriptions/resume: one `dispatch_ticket_hash` identifies the attempt throughout delivery |
| Lifecycle and recovery | Task/Hub Genesis, queries and events include the new primary facts; consumers rebuild derived indexes rather than trust imported copies |
| Governed parameter recovery | Task Genesis retains superseded parameter bodies and non-current Task/Session version overrides; refcounts and height/prune indexes are derived |
| Verification | Bounded verifier value-contradiction payloads, strict decode/digest, compact receipts, paginated query and event 30 are active at genesis; joint random-position opening remains inactive |

Each activated epoch snapshot header freezes `worker_stake_weight_ppm` and
`worker_performance_weight_ppm` (state fields 17/18, query header fields 13/14).
Their checked sum is 1,000,000; either coefficient may be zero. READY headers leave both zero.
Activation saves the applicable Worker policy once, and later parameter
updates cannot alter it. Member-weight queries and dispatch challenges combine
that saved policy with the same snapshot's member/profile facts, never current
Task parameters. Genesis and retained expired/pruned activated headers preserve
the policy. The existing pool hash commits membership; these scoring facts do
not change its registered preimage.

Task Genesis fields 90–92 preserve parameter-version behavior after governance:
`TaskParamsHistoryState` retains version/body/update/supersession heights, and two
lists share `ParamsVersionBindingState` for non-current Task and Session overrides.
An omitted object uses the imported current version. Reject duplicate or unknown
objects, current-version overrides, missing historical bodies and invalid heights;
rebuild complete private bindings, checked refcounts and both historical indexes.
The current body is stored once. A historical version with no object references
still survives through its supersession epoch, so a delayed first activation can
resolve the policy effective at its exact epoch reference height. Same-height
updates select the highest version. Retirement after that floor is bounded by
the existing visited/serialized/global budgets; referenced versions survive until
their last object retires. No fallback may reinterpret an old object using current
parameters, and explicit live-parameter exceptions keep their existing behavior.

The old NATS/BusEnvelope package, per-task Worker handraise union, Worker
assignment beacon, Builder ranking and selection anchor are retired. Verifier
handraises, future-beacon selection and verification rounds remain separate.
Task Builders are the complete immutable BuilderSet snapshot, ordered with the
dispatching Builder first and the remaining members in cyclic snapshot order.

## Canonical bytes and shared implementation

Shared FaultKind and DispatchChallengeKindV1 live in shared.v1 because Task facts
and Hub fault records both consume them. No owner-package aliases are retained.

`dispatch/` owns the generated-code-free canonical decoder, signing projections,
compact low-S signature verification, objective-evidence identity, weighted draw
and Merkle/MMR primitives. Tools import the same package. Consumers must reuse
it rather than copy signing tables, proof parsers, tree algorithms or domain
constants into their own modules. Descriptor validation checks the pinned
message tables against the schema built in CI.

The ordered projections are registered in `registry/v1/domains.json` and pinned
by language-neutral fixtures. Hashing uses existing canonical framing; raw
protobuf serialization is not a hash preimage. Nested and repeated values keep
their explicit framing, ordering and counts. An optional absent value differs
from a present zero. Detached signature bytes never enter their own digest or
the evidence identity. Signatures are raw64 low-S over the digest, except for
the separately specified recoverable wallet/EIP-712 signatures.

Account/operator identities on public protobuf APIs are canonical lowercase
`trueopen` Bech32 strings. Canonical hashing decodes them to raw20. Private Node
stores and ordered keys use validated raw address bytes; they must not persist
the presentation string or copy public DTOs as an implicit storage codec.
Hash32 is raw32 in native protobuf and storage, and descriptor-annotated `0x`
plus 64 lowercase hex in REST. The delegated EVM key address is raw20 bytes,
not a Bech32 account. Amounts use `shared.v1.Amount` with canonical unsigned
decimal atomic units; checked integer arithmetic is mandatory.

## Randomness, ordering and sticky context

The VRF input binds `chain_id, epoch, epoch_seed, session_id, order_sequence`.
The epoch is derived from the signed `earliest_submit_height`; reference height
is exactly that epoch's start. Use the registered Builder key for that epoch.
The ELL2 suite produces an 80-byte proof and 64-byte beta. Its dispatch-only
reduction is `SHA256("TRUEOPEN_DISPATCH_RANDOMNESS_V1" || 0x00 || beta)`.
This suite reduction is independent from the beacon reduction.

The draw hash is `H_FIELDS_V1("TRUEOPEN_WEIGHTED_DRAW_V1", chain_id,
"WORKER_DISPATCH", r, counter)`. Counter starts at zero, increments on every
hash attempt and is never reset between selections. Weights come from the
complete qualified pool in slot order, with checked uint64 sum and bounded
unbiased rejection sampling. Draw without replacement until the pool is empty.
Task content, a pool commitment and an availability roster do not reseed this
draw. Verifier selection retains its separately registered beacon projection.

Availability rosters only filter this order. Each round binds its own signed
root and roster; cursor and skip count continue across rounds. A refresh never
rescans earlier ranks. Sticky promotion is decided once using the first-round
roster and the pre-admission chain snapshot retained in DispatchRecordState;
later rosters only filter. A sticky candidate that rejects or times out does not
restart the draw. Only rejects/timeouts consume the skip limit.

Keeper admission verifies signatures, VRF, reference height, winner eligibility,
ticket/record consistency, deadlines, sequence and funds. It does not recompute
the whole weighted order; objective challenges do that using frozen epoch
weight inputs, the saved sticky snapshot and the first-round roster.

## Funds, delayed actions and takeover

One escrow path funds orders from session balance. Admission freezes max_fee
from balance minus frozen funds, without subtracting a pending withdrawal.
Settlement/refund releases the remainder back to the session. Deposits and
withdrawal/CLOSE require the owner wallet; delegated keys cannot move funds.
Builder preflight additionally subtracts pending withdrawals and local inflight
reservations. CLOSE stops new dispatch and waits for admitted tasks to finish;
it may replace an AMOUNT request. Maturity transfers only currently available
funds. Lifecycle expiry uses the same delayed CLOSE/refund path.

Key rotation, CLEAR, restrictive cap/expiry changes and CancelOrder register
pending changes. Same-key nonrestrictive renewal can apply immediately. Preserve
cumulative spent across all key changes. At the delayed height, cancellation of
an already consumed sequence is void. RBF remains a local Builder operation:
acceptance locks that order version; a replacement must return an explicit
accepted-or-locked outcome. Return and query effective heights for SDK key use.

A takeover entry registers a candidate but creates no Task, consumes no sequence,
freezes no funds and does not change sticky history. EndBlock activates it after
the registration-based delay only while the sequence remains unconsumed. An
accepted dispatch, effective cancellation or session closure atomically clears
the pending takeover. A second pending candidate is rejected. The two domains
`TRUEOPEN_DISPATCH_RECORD_ENTRY_V1` and `TRUEOPEN_TAKEOVER_ENTRY_V1` are separate;
takeover identity includes the candidate operator and binding generation.

## Compensation, evidence and retention

`nexus.v1.BuilderSyncService.Sync` replicates round, input chunk, attempt, record
and admitted order items using existing typed business messages. The sender signs
`H_FIELDS_V1("TRUEOPEN_NEXUS_BUILDER_SYNC_V1", chain_id, raw20(sender), canonical batch)`;
the batch also binds receiver, Session/order and immutable BuilderSet. Repeated
items preserve order, oneof tags are proto field numbers, and optionals preserve
presence. Nested business signatures remain payload. Protobuf field ordering and
explicit defaults do not change the digest. Requests are at most 1 MiB, with at
most 128 items and 128 output chunks; receivers durably acknowledge consecutive
items and the Worker's independent output sequence. Orders and winner output
replicas become available only after chain admission. Receiver membership,
accepted authority, business proofs and durable replay/conflict checks remain
consumer obligations; a valid transport signature does not assert those facts.
Validate raw request bytes before generated decoding can discard unknown or
duplicate fields. The shared verifier accepts raw bytes for this reason, so Sync
accepts binary protobuf only; JSON or other transcoded requests are rejected.
An item at an already applied sequence is an exact duplicate iff its canonical
item projection, the REPEATED_V1 element the batch signature commits to and
`dispatch.BuilderSyncItemCanonicalBytes` returns, is byte-equal to the applied
item's; otherwise it conflicts and is refused. Nested business signatures are
part of that projection; protobuf encoding is never compared. A receiver may
retain SHA-256 of those bytes as a local key, which is not a protocol identity.

Sync transport uses the current ACTIVE Builder key. Drain materials needing the
old current proof key before cutover, subject to the existing safe-activation and
response-window guards. After activation, reject old transport signatures and
re-sign retransmission batches with the new current key. Retained authenticated
or chain-accepted facts remain facts about the stable operator; do not verify
old business signatures with a new key or introduce service-key history.

Dispatch input chunks start at index 0 with positive count. Size/hash/count must
agree across chunks; reassemble in index order and verify whole-input size and
SHA-256 before use. `GetTaskEventsResponse` reports the Nexus lifecycle code set
documented on its schema, separate from Node protocol events. Its typed detail
carries takeover destinations/heights, recording Builder/task and dispatch
rejection facts for recovery without resending an order. TAKEOVER_VOIDED names
its cause: the recording Builder and recorded task, the candidate and activation
height of another takeover that registered first, the Builder the Session is
bound to, or nothing for cancellation/closure. RECORD_REJECTED always carries a
nonzero reject_code; its ticket is absent when none exists (a rejected takeover
entry, or an order whose record deadline passed before any Worker accepted). A
missed record deadline uses RECORD_LATE. Later sequences of the same Session
rejected together with an earlier entry use CONFLICT, never SEQUENCE_CONSUMED:
they were not consumed, and the client resends an order at the same sequence.
An order ahead of the next expected sequence is SEQUENCE_NOT_NEXT, also unconsumed
and resent at the same sequence; only SEQUENCE_CONSUMED retires a sequence.
New keepalive probes use odd values from Builder and even values from Cortex;
echoes retain the peer's value, including its parity.

Claims are keyed by ticket hash. A recorded winner cannot claim, and winner
ineligibility markers exclude failures attributable to the Worker. Claims check
the Builder proof, acceptance and order hash without reconstructing historical
user/session-key authorization. Payment follows a rebuttal window; penalties
and compensation are capped by the Builder account balance and create no debt.
There is no compensation-account withdrawal message in Phase 1.

An upheld dispatch fault uses the first upheld challenge_id in its objective
scope as fault_id. The scope excludes the challenger, so a second reporter
cannot collect or penalize again. Rebuild the private upheld-scope index from
challenge primaries; it does not introduce a public hash domain. In one atomic
fault application, pay any entitled omission victim first, capped at worker_max
and the account balance, then pay the independently configured penalty from
the remaining balance to Treasury. Count the actual compensation in total_paid
and actual penalty in total_penalized. Fault compensated_amount and penalty_amount
record those actual payments; fault unfilled_amount is only the penalty shortfall.
Task event 137 (EventBuilderDispatchFaultRecorded) carries the same three amounts,
so a Builder or Worker can account for the fault without querying its state.

An omission proof using a newer signed handraise_root must also supply
bound_handraise_root, the signed preimage of the round's committed root. Verify
both against the same chain/Builder, require the bound preimage's digest to match
the retained commitment, then compare (root_height, root_version) lexicographically.
The newer root height must not exceed the retained earliest_submit_height. When
the evidence root itself matches the commitment, the bound preimage is optional;
if supplied, it must still match. A digest alone cannot establish root freshness.

Four recorded-task challenges use retained records. Double dispatch can be
proved from a signed record before admission. Each challenge kind has its own
scope/deduplication key, gas cap and bounded response. Reject proofs use the current service proof key and match its signed nonce;
registration leaves that binding unchanged throughout its evidence windows;
honesty does not depend on a Worker's voluntary drain before rotation.
Preserve record/winner exclusion facts until claim
windows close and all pending claims finish. Pruned records must never be
interpreted as unrecorded tasks. Parameter updates must not reopen pruned claims.

Builder objective evidence retains exact serialized typed business messages and
uses strict decoding before any generated decoder discards unknown/duplicate
fields. Only OPEN_VERIFY and VERIFIER_ASSIGNMENT_NOTIFY are active signed
message kinds. Their shared signed binding supplies chain, stable Builder and
authorization nonce. A revoked current key may prove old facts within its admissibility windows;
it never authorizes live traffic. Pending keys cannot verify or authorize work. Proof verification
does not replace Keeper Task authority, stage, admissibility or finality checks.

Output Chunk and Fin signing projections bind dispatch_ticket_hash in addition
to chain and task hash. Every frame's ticket must match its stream header.
Worker output-equivocation evidence reconstructs the ticket from the accepted
InferReceiptV3, never from a caller's attempt copy. An old attempt's genuine frame
cannot incriminate a later attempt by the same Worker on the same signed order.

SignedHandraiseRootV1, DispatchTicketV1 and DispatchRecordV1 use the current
Builder key without an added Builder nonce. Ticket promotion is not a second
fact: sticky_applied exists only on the record and remains true if the promoted
Worker rejects and another Worker wins. Existing Cortex accept/reject nonces
and typed BuilderMessageBinding nonces remain signed and match current authority.
Shared proof verification, roster commitments and challenge identities live in
dispatch/. The unused extra dispatch-pool commitment is removed.

## Delayed key cutover

MsgRotateServiceKey registers one PendingServiceKeyRotationState per role/operator.
The old address/key/nonce stay current. The proposed next key has no live or proof
permissions before activation. Registration reserves its address and emits event
145; the existing rotated event is emitted only at actual activation. The current
key query and registration response expose the pending primary.

The inclusive old-dispatch cutoff is registration_height + 1 + the protocol hard
limit for record_deadline_blocks + max(claim_window_hard_limit + rebuttal_hard_limit,
challenge_window_hard_limit + response_hard_limit), with checked arithmetic. Use
protocol clamps rather than mutable governance values. ServiceKeyRotationSchedule
rounds strictly beyond this cutoff to an epoch start. Process activation in the
preceding block's EndBlock so all consumers see the committed binding at the epoch
start. A still-open old Task material window or insufficient global budget postpones
activation by whole epochs. Never shorten an old proof window to force a switch.
Governance cannot reopen a closed old-material batch; increasing protocol hard
limits is a separately reviewed upgrade. These hard limits require the same
pre-release calibration as the existing dispatch parameters; fixtures are examples.

Pending Cortex operators leave new Worker/Verifier duty admission. Pending Builders
stop new tickets/roots, new session bindings and new takeover bindings; bound
sessions hand over through the existing takeover path. Old-material admission and
proof windows use the ticket/record's own anchors and the frozen cutoff, never a
later live session binding. Accepted facts and ongoing group duties stay owned by
the stable operator. A pending Builder can continue on-chain group work with its
current key. Its already-frozen old Task material contexts retain the old nonce;
new Task Builder evidence contexts reserve the pending next nonce and cannot
accept old-nonce offline messages. Other available group members coordinate those
new offline contexts until activation. Same-block transaction ordering is read
from the frozen responsibility row, not inferred from Task creation height.

Activation's old-material count includes BUS_OBJECTIVE_EVIDENCE,
WORKER_OUTPUT_EVIDENCE and CHALLENGE_VERIFIER, not the pure operator duties
OPEN_VERIFY_BUILDER/SETTLE_BUILDER or reserved future-generation contexts. Rebuild
this derived count from existing responsibility primaries; no Task-wide scan is
allowed. Cortex liability/stage guards and admissible old responses also gate
activation. Proof-key lookup remains current-only. No retired service-key primary,
history prune index or governance history-expansion scan exists.

Emergency revoke stops live permission immediately, cancels pending replacement
and its address reservation, and keeps the current revoked proof identity until
its material windows close. Unactivated future-nonce Builder responsibility rows
are operator markers only, authorize no signatures and follow Task cleanup.
Builder VRF rotation uses the same hard-limit waiting and an epoch-only cutover,
while retaining its existing independent VRF audit history. It does not use the
service-material counter. Validator and first-registration next-epoch behavior
is unchanged. All of these are consumer execution requirements, not a claim that
Node implements them yet.

Hub Genesis exports pending rotations, validates their current/next nonce and
frozen heights, and rebuilds activation/address indexes and material counts. Public
addresses remain canonical Bech32 strings; private keys/values store validated raw20
addresses and raw33 public keys. Do not copy public DTOs as private storage codecs.

Roster request signatures bind chain_id and the target builder_operator. Input
requests bind dispatch_accept_digest as well as the ticket. Revoke reasons are
closed to pre-acceptance RBF. Chunk cumulative_generated_tokens is non-decreasing
within an attempt and is used only for the pre-record forwarding cap. Public
per-entry rejection codes include all order-validation failures and duplicate
challenge scopes. Record admission requires order_sequence to equal the session's
next_expected_sequence with its OrderSequenceState absent, UNUSED or
CANCEL_PENDING. A sequence ahead of next expected is SEQUENCE_NOT_NEXT: it was not
consumed, and the client resends the same sequence after the earlier ones are
recorded. A sequence behind next expected, or one holding a record or another
non-cancellable state, is SEQUENCE_CONSUMED and must never be reused. Verifier value-evidence closure uses deadline kind 14 and a
persisted verifier_value_evidence_window_closed_height before round finalization;
its close index rebuilds when close is present and closed is absent. Double-dispatch
windows use the signed record's bound_change_height, never mutable session state.

## Event routing and gap recovery

`EventTarget` is routing metadata, not permission to sign or read evidence. The
following targets are mandatory even when an event has no `session_id`. They
are derived in the event's committed state, deduplicated and ordered by role
number then raw20 address. Existing Task-party targets may be added as well.

| Codes | Required target |
| --- | --- |
| Task 132, 133, 134 (compensation claimed/paid/rebutted) | `BUILDER` at the claim's `builder_address`, `WORKER` at its `worker_operator_address` |
| Task 135, 136 (challenge opened/resolved) | `BUILDER` from `DispatchChallengeState.builder_address`, `OPERATOR` from its `challenger_address`; resolve the primary rather than infer the Builder from the challenger or task owner |
| Task 137 (dispatch fault) | `BUILDER` at the fault's Builder, plus `WORKER` when a compensated Worker is present |
| Hub 143, 144 (compensation funding / Builder VRF registration) | `BUILDER` at the named Builder |
| Hub 145 (service-key rotation registered) | `OPERATOR` at the affected operator, plus `BUILDER` targets for every member of the current BuilderSet; a rotating Builder also targets itself as `BUILDER` even when outside that set |

In particular, a pending Cortex announcement must reach the dispatching Builders;
labelling the Cortex operator's address as a `BUILDER` is not equivalent. Task
codes route through the Task role stream; Hub codes route through the protocol
stream. Clients use both streams. A global protocol subscription is also possible
but does not replace the mandatory targets. Events are hints: preflight and chain
admission still enforce the current/pending identity.

`DispatchChallengesByBuilder` and `DispatchCompensationClaimsByBuilder` recover
open items after a gap of any length. Both reuse shared height-pinned keyset
pagination and caps. Walk the two Builder-prefixed open indexes, never all
historical rows. Maintain indexes atomically with primary creation/terminal
transition/deletion; rebuild them from primary statuses on Genesis import and
check both directions. A terminal transition removes its open index immediately.
An overdue primary remains in the response until its handler actually closes it.

To recover, read every page at height H and resume event observation from H,
deduplicating by the business primary key. Restart from a fresh height if pinned
state is unavailable. Replay depth is a node deployment setting, never the sole
way to discover a legal claim/challenge or a prerequisite for mounting a defense.

## Dispatch source and transport rules

`E = earliest_submit_height / epoch_length_blocks`, without a genesis offset;
`reference_height = E * epoch_length_blocks`. `epoch_seed` is the raw R_h of that
height's committed verified beacon. Missing/unverified/placeholder sources fail
closed; no current-block, first-available-block, ZERO32 or genesis-hash substitute
exists. Epoch zero has no height-zero beacon, so dispatch starts only after the
epoch-one start beacon commits. Session funding and registration may bootstrap
before that. `ResolveEpochSeed` checks the common source/height projection;
consumers supply verified status from chain authority and use the existing
`DispatchVrfInputV1` signing projection. The fixture links source height/R_h,
epoch seed and the exact alpha used by its real ECVRF proof.

For a selected model/profile, `weight_inputs.profiles[]` is the authoritative
profile-specific source. Top-level `profile_support_fresh` and
`min_stake_snapshot` are projections of the matching entry; `candidate_weight`
uses that entry and the frozen member-level bond/performance/jail/exit inputs.
The member-wide `inference_capable` is only a summary and cannot grant capability
for a different profile. An absent matching profile is not eligible. Query,
pool construction and challenge recomputation must share this decision and
never fall back to live state. An in-pool member missing weight inputs is an
invalid snapshot. The current `VrfKey` Query intentionally has no by-epoch/history
RPC; auditors retain registration/cutover history or use archival state, and
cannot substitute a current key for an old ticket's key.

Stream bindings use schema version 1 and a fresh random 32-byte Cortex nonce.
Each direction has its own contiguous business cursors 1, 2, ... . Binding, ack
and keepalive frames carry cursor 0 and consume no business cursor. Ack 0 means
nothing acknowledged; an ack cannot cross a gap or exceed what was sent. Every
frame echoes the authenticated nonce; reconnect starts a new binding and nonce,
with business cursor 1. Do not resign or alter retained business messages.
Before processing business frames, authenticate the binding. Cursor overflow
requires reconnect, never wraparound.

A local keepalive has at most one outstanding probe, with values increasing per
direction. A received value equal to that outstanding probe is its echo: consume
it without replying. Otherwise echo the peer probe once; discard repeated peer
probe values. This rule also applies when both peers probe at once. Probe timing
and liveness thresholds remain deployment settings. The strict decoder enforces
nonce width, binding version, control/business cursor separation and binding-frame
nonce consistency; cross-frame authentication, ack bounds and liveness require
the consumer's stream state.

For `MsgRecordDispatch`, `BatchItemResultV1.object_id` is the dispatch entry digest
or takeover entry digest for that input, including NOOP. It is not the record or
ticket hash. `item_index` identifies input position. `batch_kind` is
`DISPATCH_RECORD`; the result digest uses input order and each `(object_id,status)`
pair. The published batch fixture derives these IDs from the real signed record
and accept plus a takeover entry; it does not claim funded admission by Node.

## Consumer validation

ChatCompletionOutputUsage.cached_prompt_tokens reports the input tokens served
from the prefix cache for one request. It uses int32, like the existing usage
counts, and must be between zero and prompt_tokens inclusive. Prompt and total
counts already include these tokens. Adapters map it to the OpenAI-compatible
usage.prompt_tokens_details.cached_tokens field; cache writes are excluded.
Zero means no cache reads were reported. This is consumer telemetry, never an
input to signatures, receipts, commitments or on-chain accounting. Cortex and
gateway adapters must populate/forward it from engine usage in streaming and
non-streaming responses. The cortex.v1 package remains withheld as declared in
release/packages.json; adding this field does not freeze that whole package.

Wire checks establish schema and byte conformance, not a running blockchain.
Before genesis, Node must implement atomic per-entry admission, deterministic
bounded EndBlock queues, bank/escrow conservation, current-key authorization,
replay, all Genesis/export invariants, profile weight reconstruction and cleanup
guards. Nexus/Cortex/SDK must agree on the same released bytes and exercise a
complete funded localnet workflow, including takeover, rejection, compensation,
challenge and output reconnect. Fixture parameter values are conformance
examples, not approved network defaults.

Retired field numbers/names remain reserved. No old transport fallback, legacy
session decoder or account-funded order path should be reintroduced.

## Wallet funding signatures

CreateSession signs initial_deposit and initial_builder as well as an optional
key grant. DepositSession and FundBuilderCompensation use their declared Amino
names and field shapes. WithdrawSession uses a flat selected oneof: `amount`
is the WithdrawAmountV1 object containing its Amount, or `close` is boolean
`true`. The unselected action is absent. Missing/both actions, null/false/empty
object CLOSE are rejected. Native protobuf keeps CloseSessionV1. The complete
Amino documents, Web3 typed graphs, digests and signatures are published in
`testdata/v1/task/session_funding_amino_v1.json`. Consumers share the oneof
projection machinery with registered-key SET/CLEAR instead of cloning it.
