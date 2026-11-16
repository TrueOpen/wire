# Display-only input token counts

Consumers derive the input token count from the **same accepted inference
receipt**, using the V1 token-ID encoding. This is a Worker-signed statistic
for SDK usage, explorers and indexers. It is not a new receipt field or a
chain-verified input length, and never affects billing, settlement, weights,
budgets or signing/business digests.

## Derivation and validity

Select the unique `WORKER_TOKEN_OPENING` (kind 4) entry from
`required_evidence_commitments` by kind, never by list position. Let `S` be its
`encoded_size_bytes` and `G` be that receipt's `generated_token_count`.
Each token-ID artifact is `uint32_be(count) || count * uint32_be(token_id)`.
The committed size is the sum of the input and generated artifacts:

```text
S = (4 + 4 * input_token_count) + (4 + 4 * G)
input_token_count = (S - 8) / 4 - G
```

The eight bytes are the two count prefixes. S excludes the manifest,
`generation_params`, hashes, signatures, canonical hash framing and output
text. G is not `output_leaf_count`, text length, a streamed cumulative count
or a later settlement/consensus count.

Before unsigned subtraction or division, require `S >= 8`, `(S - 8) % 4 == 0`
and `(S - 8) / 4 > G`. The resulting input count must be at least one. The
existing V1 bound of 8,388,607 tokens per artifact still applies; profile,
context, evidence-size and output-budget limits remain independent.
Do not truncate a nonintegral size, wrap an unsigned count, clamp a value,
substitute zero or fall back to Worker-reported usage.

For the published artifacts, input `[1, 256]` occupies 12 bytes and generated
`[2, 257, 65535]` occupies 16 bytes. S is 28 and G is 3, so the input count is 2.
The rule concerns token-ID artifacts, not the input text's byte length or hash.

## Source and availability

Use one of three sources for the same accepted Task/attempt: a successfully
executed, accepted `MsgSubmitInferReceipt`; its corresponding `InferReceiptState`
returned by `Query/InferReceipt` while the commitment body is retained; or a
retrieved signed `InferReceiptV3` whose recomputed canonical receipt digest
matches the chain's accepted receipt hash. Recompute that digest from the
material, including its commitment list, rather than trust a supplied hash.
A signed message in a failed transaction, mempool or optimistic relay without
this accepted-hash match is not an accepted receipt. Do not mix fields from
different receipts or attempts. If none of the three sources is available,
the count is unavailable.

The Task's locked evidence schema must select the V1 Worker token commitment
and token-ID encoding. Unknown encodings, a missing/duplicate commitment, an
invalid size/count or the absence of an accepted receipt make this statistic
unavailable. A receipt can be chain-accepted while its metadata fails this
derivation: acceptance checks the commitment envelope and bounds, not the
actual token files.

Node may prune `required_evidence_commitments` while retaining its hash/count
and the generated count. The retained hash cannot reconstruct S. Do not report
zero for a pruned or missing count; indexers retain the derived statistic when
acceptance is observed. Consumers may recover the same accepted material from
transaction history or the hash-matched signed receipt where available. This
rule adds no permanent Node storage.

S is covered by the Worker's receipt signature and the A-level commitment;
selected Verifiers check the artifacts off-chain. The chain does not establish
consensus on the derived input count. Receipt acceptance alone also does not
claim that verification has completed.

## Consumer usage and completion

After signed Fin and accepted receipt reconciliation succeeds, adapters use
the derived input count for `usage.prompt_tokens`, the same receipt's G for
`usage.completion_tokens`, and their sum for `usage.total_tokens`.
If the derivation is invalid or none of the sources retains S, omit the entire
usage object. Non-streaming responses carry no `usage` field; streaming
responses emit no usage chunk. Do not return partial completion-only usage,
zeros or Worker-reported fallback values. Otherwise confirmed content,
finish reason and tool calls remain deliverable; omitting usage is not an
output error.

Usage adds no confirmation gate or waiting period. Successful streaming
termination, including finish reason, tool calls and `[DONE]`, retains the
existing Fin/accepted-receipt reconciliation requirement whether or not
`stream_options.include_usage` was requested. With that option and available
usage, emit the usage chunk (`choices: []`) after the terminal finish-reason
chunk and before `[DONE]`; otherwise omit that usage chunk. If receipt
acceptance/reconciliation fails or times out, use the existing Provider error
and stream-termination policy, with no usage and no extended wait for it.
Non-streaming output follows the same confirmation and availability rules.

## Shared implementation and conformance

Go consumers reuse `tokenids.InputTokenCountV1(S, G)`. It performs only the
size/count derivation and V1 bounds; callers establish acceptance, schema,
commitment presence and matching identity. Its error means unavailable, not a
zero-valued statistic. API adapters apply the usage and completion rules above;
this arithmetic helper does not manage SSE or introduce a wait to dispatch or
first output.

`testdata/v1/task/token_ids_v1.json` publishes the original encoding vectors
and `input_token_count_derivation.cases`, including the linked 28-byte case,
positive boundaries, invalid/unaligned sizes, zero/negative derived counts and
uint64 extremes. `input_token_count: null` means unavailable. Decimal strings
preserve exact unsigned values across languages. The fixture verifier executes
these cases and links the base example to the actual token artifacts.

Any change to token-ID encoding must define its corresponding derivation and
conformance cases in the same change. This rule adds no proto/state/event
field, signature preimage or consensus validation.
