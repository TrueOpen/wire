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
| Verification | Bounded verifier value-contradiction payloads, strict decode/digest, compact receipts, paginated query and event 30 are active at genesis; joint random-position opening remains inactive |

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

Claims are keyed by ticket hash. A recorded winner cannot claim, and winner
ineligibility markers exclude failures attributable to the Worker. Claims check
the Builder proof, acceptance and order hash without reconstructing historical
user/session-key authorization. Payment follows a rebuttal window; penalties
and compensation are capped by the Builder account balance and create no debt.
There is no compensation-account withdrawal message in Phase 1.

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
challenge scopes. Verifier value-evidence closure uses deadline kind 14 and a
persisted verifier_value_evidence_window_closed_height before round finalization;
its close index rebuilds when close is present and closed is absent. Double-dispatch
windows use the signed record's bound_change_height, never mutable session state.

## Consumer acceptance requirements

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
