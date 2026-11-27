# Two-step sampling of the anchor audit (V1)

Status: additive contract. Nothing here is used until a network sets the two
parameters below and registers a Profile version that asks for it; every
existing Profile keeps one-step sampling unchanged.

## 1. Why

In one-step sampling the first beacon after the receipt decides both whether a
task is audited and which rows the Worker must open. A proof that checks
attention against a per-row commitment list is only sound if the list is fixed
before the audited rows are known. Two-step sampling orders the facts on chain:

```
receipt -> first beacon: coin only (selected or not)
        -> selected Worker records the hash of its commitment list (block H_L)
        -> beacons of the m heights after H_L are aggregated
        -> positions drawn; opening and proof deadlines count from the draw
        -> opening, proof and verdict exactly as in one-step sampling
```

## 2. Gate

| Layer | Rule |
|---|---|
| Profile | The `EVIDENCE_KIND_WORKER_ANCHOR_OPENING` entry of `required_infer_evidence` carries `commitment_schema_version = 2`. Version 1 is one-step sampling. The version is part of `evidence_schema_hash`, so a version-2 Profile is always a new Profile version. |
| Task | `AnchorAuditState.sampling_mode` is written as 1 at the first beacon for every task of a version-2 Profile, selected or not; otherwise it is 0. Only a selected task enters the flow below. |
| Parameters | `VerificationParamsV1.anchor_list_window_blocks` (42) and `anchor_position_beacon_blocks` (43, called m below), frozen into the task with its other parameters. Both are zero by default. m must be at least 2 and at most 256 whenever the window is set. |

An unselected task is not affected: apart from the recorded mode it gets the
same record, at the same height, as in one-step sampling, and settles at once.

## 3. Commitment list

`rows` (R) is the chain's own row count of the task: prompt tokens plus
generated tokens minus one, derived from the token commitment of the accepted
receipt. The list is exactly R entries of 32 bytes, in row order
(`list_size_bytes = 32 x R`). What an entry commits to is fixed by the
verification registration of the Profile, not by this document.

```
list_hash = sha256("TRUEOPEN_ANCHOR_KV_LIST_V1" || chain_id || task_id || u64_be(R) || list)
```

`chain_id` is its UTF-8 bytes without a length prefix; `task_id` is 32 bytes.
The chain stores `list_hash` as an opaque value and never reads the list. A
verifier recomputes it over the fetched list with the chain's R and takes the
hash, R and the positions from the chain only, never from the Worker's package.

`MsgSubmitAnchorCommitmentList`:

- signer: the current service address of the winner Worker (the rule of
  `MsgSubmitAnchorOpening`);
- accepted only for a selected, not yet final audit with `sampling_mode = 1`,
  at a height not above `list_deadline_height`;
- `list_size_bytes` must equal 32 x R; `list_uri` must lie under the audit's
  `da_uri_prefix` when one is frozen;
- the first accepted message is final. The same hash and size again is a NOOP
  (a different URI in the repetition is ignored). Any other content is refused,
  at every later stage of the audit: the list is never replaced and the
  positions are drawn once per task.

## 4. Position beacon

Let H_L be the height of the block that included the accepted list message.
The contributing heights are `F .. F + m - 1` with `F = H_L + 1`. Each
contributing value is the Hub block beacon of exactly that height and must be a
verified proposer-VRF value (`source_tag = proposer_vrf_v1`); a block-hash
placeholder is not accepted.

```
position_beacon = sha256("TRUEOPEN_ANCHOR_POSITION_BEACON_V1" || chain_id || task_id
                         || u64_be(F) || u32_be(m) || beacon(F) || ... || beacon(F + m - 1))
```

If a contributing beacon is missing or is not a proposer-VRF value when the
window ends, no position is drawn from that window. The window is restarted
with m fresh heights after the current block (`F` moves forward, the list stays
as recorded) and `EventAnchorCommitmentListRecorded` is emitted again with the
new heights. A failed window never ends the audit against the Worker, and it
never ends it in the Worker's favour while a later window still leaves the
Worker its full opening and proof time (section 6).

## 5. Position draw

```
for i = 0, 1, ... (at most 64 draws), until `count` distinct positions exist:
    p = u64_be(sha256("TRUEOPEN_ANCHOR_SAMPLE_V1" || chain_id || task_id || sample_beacon
                      || list_hash || position_beacon || u32_be(i))[0:8]) mod R
    skip p if it was drawn before
positions = the drawn values, ascending
```

`sample_beacon` is the first beacon (the one the coin was drawn from). The
draw ranges over all R rows, prompt rows included. `count` is the number of
positions per task of the network (2 in this release).

Order a verifier checks from the audit record alone:
`commitment_list_height < position_beacon_first_height <= position_beacon_last_height <= positions_height`.

## 6. Deadlines

| Deadline | Value | Written |
|---|---|---|
| `list_deadline_height` | `selection_height + anchor_list_window_blocks`, where `selection_height` is the height of the block that writes the selection: `sample_height`, or later when EndBlock sampled late. It is the first block in which the Worker can see that it was selected | at selection |
| `verdict_deadline_height` | `list_deadline_height + m + open + proof + verdict windows` | at selection, never moved |
| `opening_deadline_height` | `positions_height + anchor_open_window_blocks` | at the draw |
| `proof_deadline_height` | `opening_deadline_height + anchor_proof_window_blocks` | at the draw |

Positions are drawn only if `positions_height + open + proof + verdict windows
<= verdict_deadline_height`, so a Worker that is given positions always has its
full opening and proof windows and the validators their full voting window. A
list included in the last block of the list window meets this bound exactly
when the draw happens at its last contributing height. A draw that would not
meet it (EndBlock visited the audit late, or restarted windows used up the
slack) is not made: the audit ends NO_VERDICT.

A Worker reads every deadline from the audit record and never computes one.

## 7. Outcomes

| Situation | Verdict / source | Consequence |
|---|---|---|
| Not selected by the coin | none | settles as in one-step sampling |
| Selected, no list by `list_deadline_height` | REJECT / TIMEOUT, reason names the list deadline | the fault of a missing opening: timeout slash, no jail, task not paid |
| List recorded, positions drawn, no opening or no proof in time | REJECT / TIMEOUT | unchanged |
| List recorded, proof rejected by the vote (including a list that does not match its hash or the opened rows) | REJECT / VALIDATOR_VOTE | unchanged: reject slash, jail |
| List recorded, the chain could not draw positions in time | NO_VERDICT / TIMEOUT | Worker paid, nothing slashed |

## 8. Vectors

`testdata/v1/task/anchor_two_step_sampling_v1.json` pins the list hash, the
aggregated beacon and the draw, including a one-row task, a three-row task
(duplicates skipped), another chain id and a restarted window.
