# Tool Call Parser V1

Status: **draft** -- the markers below are not frozen until (a) reviewed against
the pinned engine's real output and (b) the `(name, version)` pair is admitted to
the governance whitelist `supported_tool_call_parsers`. See "Open items".

## Scope

This document freezes the **language-neutral behaviour specification** for each
tool-call parser `(name, version)` that a model profile may pin in
`tool_calling.parser`. It is the authority a reviewer checks the shared vectors in
`testdata/v1/parser/` against; those vectors are the executable, cross-language
encoding of this specification.

The contract common to every tool-call parser is stated in "Common contract"
below; each parser section then adds only its own markers and payload semantics.
This document does **not** cover reasoning separation (see
[Reasoning Parser V1](REASONING_PARSER_V1.md)) nor the `output_decoding` layer
(token IDs to committed output), which is a per-model artifact, not a shared
parser vector.

## Common contract (all tool-call parsers)

```text
Input    : committed output, a UTF-8 string already verified by the SDK
           (frame signatures + contiguous seq + final MMR root == receipt output hash).
           When a reasoning parser is also pinned, the input is the remainder
           after reasoning separation (REASONING_PARSER_V1; pipeline order fixed:
           reasoning first, then tool). Otherwise it is the whole committed output.
Output   : { content: string, tool_calls: [ { name: string, arguments: string } ] }
           - arguments is a JSON-object string, byte-identical across Go / Rust / TS.
           - id / type / index are Provider-synthesised (per call_id_format) and
             are NOT part of this spec or the cross-language comparison.
Failure  : malformed markers / illegal JSON degrade to plain text -- the offending span
           is emitted as content, no protocol error. An unclosed block (start marker, no
           close) likewise degrades to content by default; a parser section MAY define a
           recovery of the buffered payload into a tool_call, gated on a verified,
           model-initiated stop finish_reason (from the signed Fin: EOS / stop token /
           stop sequence -- never MAX_* truncation, never user stop). That verified
           finish_reason is the only input beyond committed output; it keys the
           deterministic result alongside (name, version). See hermes@1 and Open item 3.
Unpinned : if the SDK does not support the pinned (name, version), or the manifest
           cannot be fetched / its hash does not match the chain, the parser is
           treated as unpinned: committed output is emitted verbatim as content and
           no format is guessed.
Streaming: a state machine. Plain bytes stream as content; on a start marker,
           buffer until the close marker, then emit one tool_call. Split points
           (by byte / token / marker boundary) must not change the final
           concatenated result. Pre-confirmation (optimistic) delivery is out of
           scope here; vectors compare the final result only.
```

## Parsers

### hermes@1

```text
name    : hermes
version : 1
markers : start = "<tool_call>", end = "</tool_call>"
payload : between the markers, a single JSON object { "name": <string>,
          "arguments": <object> }. Surrounding whitespace / newlines are trimmed
          to locate the JSON; arguments is captured as its exact object substring.
call_id : profiles pinning hermes@1 set call_id_format = OPENAI_CALL_PREFIX.
multiple: zero or more <tool_call> blocks; text outside blocks is content,
          concatenated in order.
noargs  : `name` (a string) is required; a block whose JSON has no valid `name` is
          malformed -> content. If the `arguments` key is absent, arguments defaults to
          "{}" (empty object, matches Dynamo). An `arguments` present but not an object
          is malformed -> content.
recover : an unclosed `<tool_call>` (no `</tool_call>`) whose buffered payload is a
          complete, valid JSON object is recovered as that tool_call iff a verified,
          model-initiated stop finish_reason is present (from the signed Fin: EOS /
          stop token / stop sequence; never MAX_* truncation, never USER_STOP). Absent
          or non-qualifying finish_reason -> the span is content. This is the
          finish_reason-gated recovery from the common contract, and it matches the
          vLLM / Dynamo hermes recovery (reference cases).
```

Example:
`<tool_call>\n{"name":"get_weather","arguments":{"city":"São Paulo"}}\n</tool_call>`
becomes `content=""`,
`tool_calls=[{name:"get_weather", arguments:"{\"city\":\"São Paulo\"}"}]`.

> **TBD before freeze**: exact whitespace handling inside/around the JSON, behaviour
> on multiple adjacent blocks, nested-brace / string-escaped `</tool_call>` inside
> arguments, and whether the *raw-JSON-without-tags* fallback -- bare JSON with no
> `<tool_call>` tags at all -- that vLLM's hermes parser accepts is part of hermes@1 or
> excluded. (This raw-no-tags leniency is a *different* leniency from the unclosed-but-
> complete recovery above, which is already specified and finish_reason-gated.) Resolve
> against the pinned engine, then remove this note.

### qwen3_coder@1

Unlike hermes@1 it does **not** carry a JSON object; arguments are expressed as
nested XML elements that the SDK must assemble into the JSON arguments string.

```text
name    : qwen3_coder
version : 1
markers : outer start = "<tool_call>", outer end = "</tool_call>"
          function    = "<function=NAME>" ... "</function>"
          parameter   = "<parameter=KEY>" VALUE "</parameter>"
payload : name = NAME from <function=NAME>; arguments assembled from each
          <parameter=KEY>VALUE</parameter> into a JSON object string
          { "KEY": "VALUE" }, ordered by appearance. Every VALUE is emitted as a JSON
          **string** verbatim from the committed output -- no type coercion (number /
          bool / nested-JSON) and no tool-schema lookup. Typing is the consumer's job;
          this keeps arguments a pure, deterministic function of (committed output,
          name, version) -- values derive from committed-output text only, byte-identical
          across Go / Rust / TS. A <function=NAME> with no <parameter> yields "{}".
call_id : OPENAI_CALL_PREFIX.
multiple: zero or more <tool_call> blocks; text outside blocks is content.
```

> **(a) value type coercion -- RESOLVED**: qwen3_coder@1 emits every VALUE as a JSON
> string, verbatim from committed output; no number / bool / nested-JSON coercion and no
> tool-schema lookup. Schema coercion would break the text-only derivation and the
> cross-language determinism (same output + version -> same result), and would force the
> vectors to carry `tools`; the consumer does any typing.
>
> **TBD before freeze (higher risk than hermes)**: (b) whitespace/newline trimming of
> VALUE; (c) multiple functions per <tool_call> block vs one; (d) escaping of < / >
> inside VALUE; (e) truncation may omit the closing </parameter> (or </function>), not
> only </tool_call> -- define the partial recovery. The exact format lives in the
> model's chat template; resolve against it and the pinned engine, then remove this note.
>
> **Engine-mapping note.** In vLLM this <function=...><parameter=...> format is served
> by different flags across versions/frontends (`qwen3_coder` and `qwen3_xml` both
> exist and differ between the Python and Rust frontends). TrueOpen freezes the
> format under the canonical name qwen3_coder@1; each node maps that canonical name
> to whichever local engine flag actually produces this format.

## Shared vector file

One file per `(name, version)`:
`testdata/v1/parser/tool_call_hermes_v1.json` and
`testdata/v1/parser/tool_call_qwen3_coder_v1.json`, each registered in
`testdata/v1/manifest.json`, carrying `"origin": "wire"` and a `contract_section`
pointing at this document. CI recomputes every case in Go / Rust / TS and asserts
byte-identical content / tool_calls.

Each vector entry:

```text
{ "name": <case id>,
  "input_utf8": <committed-output string>,
  "finish_reason": <FinishReasonV1 or null>,   // optional; null/absent = pure path.
                                               // only a model-stop value drives recovery.
  "expected": { "content": <string>, "tool_calls": [ {"name":..., "arguments":...} ] },
  "stream_splits": [ [<byte offsets>], ... ]   // optional; each split must yield expected
}
```

### Required cases

| Class | Case | Expected |
|---|---|---|
| Positive | single block, no surrounding text | content empty, 1 tool_call |
| Positive | text before + block + text after | content = concatenated text, 1 tool_call |
| Positive | two blocks | 2 tool_calls in order |
| Positive | non-ASCII arguments (e.g. São Paulo) | arguments bytes preserved |
| Positive | block with `name` only, no `arguments` key | 1 tool_call, arguments "{}" |
| Negative | block whose JSON has no valid `name` | malformed, span as content, 0 tool_calls |
| Negative | no marker at all | content = whole input, 0 tool_calls |
| Negative | start marker, no close; finish_reason null / `length` / user-stop | buffered span flushed as content, 0 tool_calls |
| Positive | start marker, no close, complete JSON, model-stop finish_reason | recovered as 1 tool_call (vLLM / Dynamo parity) |
| Negative | illegal JSON inside block | block span as content, 0 tool_calls |
| Streaming | JSON split across frames mid-arguments | same final result as non-stream |
| Streaming | multi-byte char split on frame boundary | incremental-decode rule holds, concat unchanged |

For `qwen3_coder@1` the same classes apply, plus: single `<parameter>`, multiple
`<parameter>` (argument order preserved), numeric / boolean-looking VALUE stays a JSON
string (no coercion), and split across the `<parameter=...>` boundary in streaming.

## Open items

1. Freeze markers & whitespace against the pinned engine; remove the TBDs above.
2. Governance: `(hermes, 1)` and `(qwen3_coder, 1)` must be in
   `supported_tool_call_parsers` before a profile can pin them.
3. finish_reason is out of scope **except** the verified, model-initiated stop
   finish_reason that gates unclosed-call recovery (common contract / hermes@1). That
   value comes from the signed Fin (verified terminal metadata) -- no new input into
   committed output. transport id / index / type remain out of scope (separate proposal).
