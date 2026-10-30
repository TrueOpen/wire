# Registered Session Keys V1

This contract permits a wallet to register a delegated signer for
one session. Consumers pin the published wire release before activation.
The client generates the key and must not derive it from a wallet
signature. Key registration stores an address, never a private key. Phase 1
session funds have a separate escrow ledger; see [the contract](PHASE1_CONTRACT.md).
The same address may be registered independently on multiple sessions; there is
no key-to-session uniqueness index. Each session enforces its own authorization.

## Schema

| Owner | Additions |
| --- | --- |
| `task.v1.MsgCreateSession` | Field 2, optional `SessionKeyGrantV1` message |
| `SessionKeyGrantV1` | 1 `session_key` raw20, 2 `expiry_height`, 3 `spend_cap` Amount |
| `MsgUpdateSessionKey` | 1 `signer_address`, 2 `session_id`, action oneof: 3 `set`, 4 `clear` |
| `MsgUpdateSessionKeyResponse` | 1 optional `session_key_or_empty`, 2 `expiry_height`, 3 `spend_cap`, 4 `spent`, 5 `set_height`, 6 `status` |
| `StreamState` | 7 optional `session_key`, 8 `session_key_expiry_height`, 9 `session_key_spend_cap`, 10 `session_key_spent`, 11 `session_key_set_height` |
| `SessionParamsV1` | 11 `max_session_key_blocks` |
| Public event 106 | `EventSessionKeyUpdated`: 1 `session_id`, 2 `owner`, 3 optional `session_key_or_empty`, 4 `expiry_height`, 5 `spend_cap`, 6 `spent`, 7 `set_height` |

Native protobuf uses raw bytes. REST projects raw20 key addresses as ProtoJSON
Base64, Hash32 session IDs as `0x` plus 64 lowercase hex, owners as canonical
Bech32, and amounts through `shared.v1.Amount`. A present key must be exactly
20 bytes, not the zero address, and differ from the owner's raw address. Absence means no key;
an explicitly present empty key is malformed.
Amounts supplied in a grant use canonical unsigned decimal atomic_units;
unlimited mode is the explicit value `"0"`, not an empty amount string.

## Registration and mutation

The owner signs CreateSession or UpdateSessionKey as a Cosmos transaction. An
ACTIVE/IDLE session accepts updates; CLOSED rejects even while its row remains
retained. The session key does not acquire the owner's transaction permissions.
An update requires exactly one SET or CLEAR action.

SET requires `base_height < expiry <= base_height + max_session_key_blocks`,
with checked addition and a positive current effective parameter. Creation and
immediate renewal use the current height; a delayed SET uses its scheduled
effective height, so the key is valid when it activates. Historical session-pinned
parameters are not consulted for this input bound. Governance changes affect
later registrations/renewals, not already granted expiry heights. Deployments
choose the limit; no seven-day default is frozen here.

Initial creation can register a key immediately. Later SET/CLEAR and restrictive
cap/expiry changes register PendingSessionKeyChangeV1 with an effective height.
Nonrestrictive same-key renewal can apply immediately. Pending state and effective
height are returned by UpdateSessionKey and QuerySession. The old key remains the
chain authorization until activation; SDKs switch at that height. Builders reject
new work conservatively after a pending CLEAR or cap reduction.

Applying a different key or SET after CLEAR records the effective height as
set_height. Same-key renewal preserves it. CLEAR removes the key and zeroes
expiry/cap/set_height. Every change preserves cumulative spent; exact unchanged
updates return NOOP without an event. Already admitted tasks stay authorized.
Requested and effective events distinguish registration from activation.

## Wallet registration signing

The canonical Legacy Amino message uses the declared `amino.name` and a flat
value. CreateSession commits initial_deposit and initial_builder, and adds
`session_key` only when a grant is present.
UpdateSessionKey includes `signer_address`, `session_id`, and exactly one action:
`set` is the grant object; `clear` is the boolean `true`. The unselected action
is absent. Missing/both actions, null actions, `clear: false` and `clear: {}` are
invalid Amino update forms. Native protobuf CLEAR remains ClearSessionKeyV1.

In this signing projection, byte arrays (including session_id) are standard
Base64, uint64 expiry is a decimal string, and spend_cap is the Amount object
with canonical decimal atomic_units. These are Amino signing bytes; REST's
Hash32 rendering is a different projection. Canonical sign documents sort JSON
keys. Web3 signing uses the existing Cosmos Web3 transaction domain and Tx
projection, with the selected action committed to the typed message. A boolean
CLEAR avoids empty struct types with inconsistent wallet/library encodings.
`task/session_key_amino_v1.json` freezes the complete creation/SET/CLEAR sign
documents, typed graphs, domain separators, digests and wallet signatures.

## First order admission

SignedOrderV2 retains its four fields and existing EIP-712 version 3 digest.
Recovering to the order's user selects the existing wallet/public-key path.
Otherwise require the session's current key. The owner public-key prerequisite
and the session owner/order user equality remain on both paths. A delegated
order also requires:

1. Current height is at or before the registered expiry.
2. Its signed session_anchor_height is at or after registration height. The
   retired session_anchor_block_hash is absent; freshness uses signed
   earliest_submit_height and the dispatch deadline rules.
3. Checked `spent + max_fee` does not exceed a nonzero cap. Cap zero is unlimited,
   but never waives checked arithmetic, session available balance or other admission rules.

The count is cumulative authorized max_fee, not actual expenditure. Increment
once, including unlimited grants, atomically with sequence consumption, escrow
reservation and the remaining admission writes. Rejection rolls everything back.
Wallet orders, exact replay, later proposals, refunds and settlement do not
increment it. Rotation, renewal and CLEAR never reset it. A positive cap below
spent prevents new delegated admission; zero explicitly enables unlimited mode.

Return `ERR_SESSION_KEY_INVALID` for a mismatched key or pre-registration
anchor, `ERR_SESSION_KEY_EXPIRED` for expiry, and
`ERR_SESSION_KEY_SPEND_CAP_EXCEEDED` for a cap failure. A non-owner signer with
no current registration also returns `ERR_SESSION_KEY_INVALID`, including after
CLEAR. Preserve these errors through
the ABCI result instead of wrapping them as generic dispatch rejection.

Authorization is an admission-time condition. Accepted tasks retain their
frozen scope across rotation, CLEAR, expiry, cap changes and export/import.
Genesis validation must not compare historical accepted orders with the current
key, cap or expiry. The unchanged sequence and owner checks still prevent replay.

## Off-chain grants and registered requests

SessionGrantV1 remains the existing short-lived off-chain request authorization;
it does not itself authorize an order. Registered keys may instead sign the
session request allowlist without a grant. sessionGrantHash is then 32 zero
bytes; the existing request domain, body binding, freshness and replay rules
are unchanged. Requests never increment the authorization counter.

The no-grant registered-key branch checks session existence/status, owner and
recovered key, then expiry, then the method allowlist. SDK requests resolve the
envelope session; Task Data requests resolve this Builder's local Task record
and allow only OUTPUT Metadata/Fetch. Missing local identity or unavailable
chain state rejects. Positive and negative cache entries carry read heights
and a configured block expiry; disconnect clears the cache, and authorization
events invalidate it. Apply ingress rate limits to cache misses.

OpenTask prechecks delegated orders before input storage, but Keeper is final
authority. A later local assignment rejection may emit RECORD_REJECTED; it is
not proof another Builder did not obtain on-chain acceptance. Recovery checks
committed sequence state and resigns the same unconsumed sequence. Rotation uses
the new key, CLEAR uses the wallet, and expiry/cap failure first requires an owner
grant update. Local terminal-task retry support is a separate Nexus requirement;
it does not introduce order fields or require consuming a sequence via cancellation.

## Consumer and release boundary

Phase 1 changes this contract through a fresh genesis. Wire freezes bytes; Node
must implement delayed authorization, prefunded escrow, per-entry admission,
event routing, retained facts and export/import invariants. Nexus/Cortex/SDK
must use the same immutable released descriptor and complete coordinated localnet
acceptance before enabling delegated dispatch. There is no retained-data upgrade
or historical parameter decoder in this contract. See PHASE1_CONTRACT.md for
all changed preimages, release boundaries and consumer requirements.
