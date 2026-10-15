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
Failure  : malformed / unclosed markers / illegal JSON degrade to plain text --
           the offending span is emitted as content, no protocol error.
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
```

Example:
`<tool_call>\n{"name":"get_weather","arguments":{"city":"São Paulo"}}\n</tool_call>`
becomes `content=""`,
`tool_calls=[{name:"get_weather", arguments:"{\"city\":\"São Paulo\"}"}]`.

> **TBD before freeze**: exact whitespace handling inside/around the JSON, behaviour
> on multiple adjacent blocks, nested-brace / string-escaped `</tool_call>` inside
> arguments, and whether the raw-JSON-without-tags fallback that vLLM's hermes
> parser accepts is part of hermes@1 or excluded. Resolve against the pinned engine,
> then remove this note.

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
          { "KEY": <coerced VALUE> }, ordered by appearance.
call_id : OPENAI_CALL_PREFIX.
multiple: zero or more <tool_call> blocks; text outside blocks is content.
```

> **TBD before freeze (higher risk than hermes)**: (a) value type coercion -- VALUEs
> are emitted as plain text; decide whether qwen3_coder@1 keeps them as JSON strings
> or coerces to number/bool/nested-JSON per the tool schema; (b) whitespace/newline
> trimming of VALUE; (c) multiple functions per <tool_call> block vs one; (d) escaping
> of < / > inside VALUE; (e) truncation may omit the closing </parameter> (or
> </function>), not only </tool_call> -- define the partial recovery. The exact format
> lives in the model's chat template; resolve against it and the pinned engine, then
> remove this note.
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
| Negative | no marker at all | content = whole input, 0 tool_calls |
| Negative | start marker, no close (truncation) | buffered span flushed as content, 0 tool_calls |
| Negative | illegal JSON inside block | block span as content, 0 tool_calls |
| Streaming | JSON split across frames mid-arguments | same final result as non-stream |
| Streaming | multi-byte char split on frame boundary | incremental-decode rule holds, concat unchanged |

For `qwen3_coder@1` the same classes apply, plus: single `<parameter>`, multiple
`<parameter>` (argument order preserved), non-string value coercion (once TBD
resolved), and split across the `<parameter=...>` boundary in streaming.

## Open items

1. Freeze markers & whitespace against the pinned engine; remove the TBDs above.
2. Governance: `(hermes, 1)` and `(qwen3_coder, 1)` must be in
   `supported_tool_call_parsers` before a profile can pin them.
3. finish_reason and transport id / index / type are explicitly out of scope
   (separate termination-metadata proposal).
