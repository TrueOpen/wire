# Model support confirmation relay

`nexus.v1.IngressAPI.SubmitModelSupportConfirmation` lets Cortex submit its
service-key-signed support refresh to a Builder that signs and pays for the
outer `hub.v1.MsgBatchConfirmModelSupport` transaction. It is independent of
Tasks, dispatch streams, standing handraises and SDK wallet authentication.
A stale support row must not prevent submitting an otherwise valid refresh.
This endpoint cannot declare support, activate a model or change capabilities.
The consumer implementation is tracked in
[Nexus #60](https://github.com/TrueOpen/nexus/issues/60).

## Payload and signing

The request contains `epoch_index` and `confirmation`. The latter is protobuf
binary of the existing `hub.v1.ModelSupportConfirmationV1` defined in
`hub/v1/msg_registry.proto`; it is neither JSON, `Any` nor a batch transaction.
The outer request's ProtoJSON projection represents these bytes as Base64.
This follows the existing `OpenTaskHeader.order_envelope` transport pattern:
the Hub type stays in Hub, Nexus imports no Hub descriptor, and there is no
parallel confirmation DTO. No existing field, signing byte or chain message
changes.

Decode the confirmation using its existing schema and bounded input handling.
Reject an empty or malformed payload, unknown fields, duplicate singular
fields and wrong wire types rather than silently accepting ambiguous input.
Field order and equivalent protobuf serialization do not change its identity;
the model list order does. The five fields remain:

1. `operator_address`: canonical lowercase `trueopen` Bech32, decoding to raw20.
2. `supported_models`: nonempty, strictly ascending, unique raw32 model IDs.
3. `service_authorization_nonce`: the operator's current binding nonce.
4. `expiry_height`: inclusive authorization expiry in blocks.
5. `service_signature`: the original raw64 low-S current service-key signature.

Reuse `TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1` from `registry/v1/domains.json`.
Its preimage is the existing `H_FIELDS_V1` projection of chain ID, decoded raw20
operator, request epoch, service nonce, expiry, uint32 model count and the
canonical repeated model frame. The signature, submitter and protobuf envelope
are not part of that digest. Return the digest as `0x` plus 64 lowercase hex
digits in `confirmation_signing_digest`.

`epoch_index` must equal the chain's current epoch. The word "daily" does not
define a UTC day or a fixed wall-clock interval. Use chain height, epoch and
live Hub parameters, including `max_service_material_expiry_blocks` and the
support limits; do not hard-code a refresh interval or borrow Task timeouts.
For a given epoch, Cortex retries the same signed model list instead of
re-signing it on every retry. Different material conflicts while that
operator/epoch has a valid queued confirmation or a chain-accepted row.

## Validation and bounded batching

Before accepting a request, read current chain state and validate the canonical
fields, registered Cortex operator, current service key and nonce, signature,
epoch, expiry and applicable support-refresh eligibility. `support_active=true`
is not a blanket prerequisite: ordinary recoverable jail may refresh freshness
without restoring duty eligibility, and stale support is why renewal exists.
Model rows that the existing chain handler skips remain unrefreshed; do not
treat an accepted confirmation as activation or successful renewal of those rows.
Never use a previous key or trust a caller-supplied public key. Check the
existing Hub limits on confirmation count, total model items, supported models
per operator and encoded batch bytes. Even a one-item batch must fit, including its outer
`epoch_index` and relayer `submitter_address` overhead. Unavailable chain state
or a full relay queue returns an RPC error without acknowledging acceptance.

Batch only confirmations for the same current epoch. Sort confirmations by
decoded operator raw20 bytes and keep operators unique; do not sort by Bech32
text. Preserve each signed model list, nonce, expiry and signature; never split
one confirmation's model list across transactions. Multiple bounded batches
may be submitted in one epoch. The Builder fills its own `submitter_address`,
signs the outer transaction and pays gas; it cannot re-sign Cortex material or
extend its expiry.

Flush on a bounded timer or size limit, with time for inclusion before the
earliest signature expiry and the epoch boundary. Never wait for an entire
epoch to collect a batch. Recheck live keys, nonces, epochs, expiry, eligibility
and batch limits before broadcast. The chain remains authoritative: stale or
invalid material can reject an atomic batch. Isolate failed items, revalidate
the remaining confirmations and retry within their original validity windows;
do not mark every queued item successful because a transaction was broadcast.

## Replay, acknowledgements and recovery

Scope replay state by chain, decoded operator and epoch, matching the existing
on-chain `DailySupport` row. An identical signing digest **and identical raw64
signature** is an idempotent retry, even when protobuf field order differs.
Different signed material for an occupied operator/epoch conflicts; do not
silently replace it, merge model lists or allow a nonce change to create a
second row. Compare against both queued and chain-accepted material. A row's
stored `signature_digest` is SHA-256 of the raw64 signature, not the signing
digest. Every retry must still pass live validation; a cached acknowledgement
cannot authorize an expired epoch, retired key or expired signature.

Use gRPC `INVALID_ARGUMENT` for malformed payloads, `UNAUTHENTICATED` for invalid
service signatures, `FAILED_PRECONDITION` for stale epoch/key/expiry or failed
refresh eligibility, `ALREADY_EXISTS` for conflicting material,
`RESOURCE_EXHAUSTED` for configured size/queue limits and `UNAVAILABLE` when
required chain state cannot be read. An exact valid retry returns success with
`relay_accepted=true` and `idempotent=true`; a newly queued item uses
`idempotent=false`. Errors must not be encoded as an accepted response.

`relay_accepted=true` acknowledges local relay acceptance or an existing chain
acceptance. It is not an inclusion receipt, renewal guarantee or declaration
that every listed model refreshed. A confirmation may refresh no model rows.
The caller must observe `DailySupport` and each intended `ModelSupport` row,
including `support_fresh_until_epoch`, using the existing Hub queries/events.
Renewal is complete only when the intended rows have the expected freshness.

Queue loss, restart, transaction failure and epoch rollover are recoverable by
querying chain state and retrying identical material while it remains valid.
After rollover or an invalidated key/expiry, obtain current chain state and sign
fresh material; the Builder cannot repair it. Within the same epoch, first
query `DailySupport`: a chain-accepted row cannot be replaced. An unsubmitted
queue entry whose key or expiry has become invalid may be retired only after
an authoritative query at or after invalidation confirms no chain-accepted
row; then newly valid material can occupy the empty slot. Do not evict a valid
queued item or use a stale query to race an in-flight transaction.
A Cosmos-capable Cortex may submit the same batch itself with a funded fee payer. A file-key-only Cortex
uses a relay and needs no fee account. This RPC changes neither the chain's
replay rules nor its support eligibility and does not grant initial activation.
