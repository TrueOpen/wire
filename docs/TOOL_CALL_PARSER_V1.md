# Tool Call Parser V1

Status: **draft** -- not frozen until the `(name, version)` pair is admitted to the
governance whitelist `supported_tool_call_parsers`. See "Open items".

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
           All positions and matching below are on bytes; markers are ASCII.
Output   : { content: string, tool_calls: [ { name: string, arguments: string } ] }
           - arguments is a JSON-object string, byte-identical across Go / Rust / TS.
           - id / type / index are Provider-synthesised (per call_id_format) and
             are NOT part of this spec or the cross-language comparison.
Whitespace: wherever this document says "whitespace" it means exactly the ASCII
           bytes SP (0x20), HT (0x09), LF (0x0A), CR (0x0D); no Unicode space is whitespace.
Blocks   : the input is scanned left to right. A block opens at a start marker and
           closes at the first end marker after it; the end marker is matched on bytes,
           whether or not it sits inside a JSON string or a parameter value. A start
           marker inside an open block is payload bytes, not a new block. An end marker
           outside any block is plain text.
Content  : the text outside blocks, plus the raw bytes (markers included) of every
           block that yields no tool_call, concatenated in input order. A segment of
           text outside blocks that lies between two blocks, or after the last block,
           and is whitespace only, is layout and is dropped. All other outside text,
           including text before the first block, is kept verbatim.
Failure  : a closed block whose payload breaks its parser section's rules is
           malformed: it yields no tool_call and its raw bytes are content (see
           Content), no protocol error. Other blocks are unaffected. An unclosed block
           (start marker, no close) likewise degrades to content by default.
Recovery : a parser section MAY define recovery of an unclosed block into tool_calls
           only within these limits:
           - gate: the verified finish_reason, taken from the signed Fin
             (TRUEOPEN_OUTPUT_FIN_V1), is EOS_TOKEN, STOP_SEQUENCE or STOP_TOKEN.
             MAX_OUTPUT_TOKENS, MAX_OUTPUT_DURATION, USER_STOP or no verified
             finish_reason -> no recovery.
           - input: that finish_reason is the only input beyond committed output. The
             payload is judged on the raw committed-output bytes of the unclosed block;
             no order stop sequence is stripped (on STOP_SEQUENCE the stop string, and the
             rest of the last token, are still in committed output).
           - the parser section states which payload recovers, how many tool_calls it
             yields, and what happens to a trailing partial close marker. A parser section
             that defines no recovery never recovers.
           The deterministic result is keyed on (committed output, name, version,
           verified finish_reason).
Support  : an SDK supports a profile's tool-call parser only if it supports the pinned
           (name, version) and, when the profile also pins a reasoning parser, supports
           that reasoning parser too. Otherwise the tool-call parser counts as unsupported
           for that profile. This keeps a call the model wrote while reasoning from being
           parsed when the reasoning span cannot be separated (REASONING_PARSER_V1).
Unpinned : if the SDK does not support the profile's tool-call parser (see Support), or
           the manifest cannot be fetched / its hash does not match the chain, the parser
           is treated as unpinned: its input is emitted verbatim as content and no format
           is guessed.
Streaming: a state machine. Plain bytes stream as content; on a start marker, buffer
           until the close marker, then emit that block's tool_calls (or, if it yields
           none, its raw bytes as content). Whitespace after a block is held until it is
           known whether it is layout. Split points (by byte / token / marker boundary)
           must not change the final concatenated result. Pre-confirmation (optimistic)
           delivery is out of scope here; vectors compare the final result only.
```

## Parsers

### hermes@1

```text
name    : hermes
version : 1
markers : start = "<tool_call>", end = "</tool_call>"
payload : the bytes between the markers, with leading and trailing whitespace trimmed,
          must be exactly one JSON object (strict JSON, below) and nothing else.
          - "name": required, a JSON string; the tool_call name is its decoded value.
          - "arguments": optional. If present it must be a JSON object, and the
            tool_call arguments are its exact bytes in the input, from its "{" to the
            matching "}", unchanged (no re-serialisation). If absent, arguments is "{}".
            Present but not an object (null included) -> malformed.
          - any other top-level key is ignored. "parameters" is not an alias for
            "arguments".
          - top-level keys are matched on their decoded value, so "arguments" is
            "arguments"; the raw substring rule applies to the value, not the key.
strict JSON: RFC 8259, with JSON whitespace = the four whitespace bytes above. The
          block is malformed if any of these holds anywhere in the payload:
          - not valid JSON, or trailing bytes after the object;
          - the top-level object has "name" or "arguments" more than once;
          - a string contains a \u escape for an unpaired surrogate (D800-DFFF not
            forming a valid high-low pair);
          - nesting of objects / arrays deeper than 64 (the top-level object is
            depth 1).
          Beyond these, validity is the RFC 8259 grammar only: number magnitude and
          precision are not checked, and duplicate keys below the top level (inside
          "arguments") are allowed -- arguments is passed through, not decoded.
call_id : profiles pinning hermes@1 set call_id_format = OPENAI_CALL_PREFIX.
multiple: zero or more blocks, each yielding one tool_call in input order; content
          follows the common-contract Content rule.
recover : only through the common-contract gate. The unclosed block is the block still
          open at end of input: it runs from the `<tool_call>` that opened it to the end
          of input, and a later `<tool_call>` inside it is payload bytes, not a new block.
          The payload is the bytes after that opening `<tool_call>`, with leading and
          trailing whitespace trimmed. It recovers as exactly one tool_call iff it meets
          the closed-block payload rules above. Otherwise the block's raw bytes, from its
          `<tool_call>` to end of input and untrimmed, are content.
          A trailing partial close marker (e.g. `</tool_`) is not stripped: it makes the
          payload invalid JSON, so that block does not recover. On STOP_SEQUENCE the stop
          string is part of the payload; if it leaves the JSON invalid, no recovery.
```

Bare JSON with no `<tool_call>` markers is not a tool call: it is content.

Example:
`<tool_call>\n{"name":"get_weather","arguments":{"city":"São Paulo"}}\n</tool_call>`
becomes `content=""`,
`tool_calls=[{name:"get_weather", arguments:"{\"city\":\"São Paulo\"}"}]`.

The Qwen3 template renders a call as `<tool_call>\n{"name": "…", "arguments": …}\n</tool_call>`
and puts `\n` between consecutive blocks (and after any text before the first one); the
trimming and Content rules above recover exactly those calls, and content is that
leading text verbatim, including the `\n` the template put after it.

**Reference-engine divergences** (informative). vLLM's `hermes` parser re-serialises
`arguments` (`json.dumps`, so `{"a": 1}` with spaces), keeps only the text before the
first block as content, and on any bad block returns the whole output as content with
no calls; it also recovers an unclosed block regardless of finish_reason. Dynamo's
`hermes` keeps the raw `arguments` substring but accepts `parameters` as an alias and
drops an unparseable block instead of surfacing it. `hermes@1` keeps the raw
substring, keeps all outside text, and isolates a bad block to itself.

### qwen3_coder@1

Unlike hermes@1 it does **not** carry a JSON object; arguments are expressed as
nested XML elements that the SDK assembles into the JSON arguments string.

```text
name    : qwen3_coder
version : 1
markers : outer start = "<tool_call>", outer end = "</tool_call>"
payload : the bytes between the outer markers must match, exactly:
            payload   = ws* function ( ws* function )* ws*
            function  = "<function=" NAME ">" ws* ( parameter ws* )* "</function>"
            parameter = "<parameter=" KEY ">" VALUE "</parameter>"
          where ws is a whitespace byte and:
          - NAME / KEY: the bytes up to the next ">", raw (not trimmed); must be
            non-empty and must not contain "<" or LF (such a name can only come from a
            tag the model never finished).
          - VALUE: the bytes up to the first "</parameter>"; then exactly one leading
            LF and exactly one trailing LF are removed if present. Nothing else is
            removed, and nothing is unescaped (no HTML entities, no backslash escapes).
            A VALUE therefore cannot contain the literal "</parameter>"; "<", ">",
            "<parameter=" and "</function>" inside it are plain bytes.
          Malformed (the whole block yields no tool_call) if the payload does not match
          that shape -- e.g. no function, text other than whitespace between elements, no
          "</parameter>" left in the block for an open parameter, a missing
          "</function>", spaces inside a tag such as "<parameter = k>" -- or if a KEY
          repeats within one function. An omitted "</parameter>" followed by a later one
          is not malformed by itself: the VALUE runs on to that later "</parameter>",
          taking the next "<parameter=...>" with it as plain bytes.
tool_call: each function yields one tool_call, in input order: name = NAME;
          arguments = a JSON object with one member per parameter, in order of
          appearance, KEY -> VALUE, every VALUE a JSON **string** -- no type coercion
          (number / bool / nested JSON) and no tool-schema lookup. A function with no
          parameter yields "{}".
encoding: arguments is written byte for byte as follows, so Go / Rust / TS agree:
          - "{" member ( "," member )* "}" or "{}", with no whitespace anywhere;
            member = string ":" string;
          - string = '"' + escaped bytes + '"', where: '"' -> \" ; '\' -> \\ ;
            BS -> \b ; FF -> \f ; LF -> \n ; CR -> \r ; HT -> \t ; any other byte
            0x00-0x1F -> \u00 + two lowercase hex digits; every other character,
            including "<", ">", "&", "/", 0x7F, U+2028, U+2029 and all non-ASCII, is
            copied as its UTF-8 bytes.
call_id : OPENAI_CALL_PREFIX.
multiple: zero or more blocks, one or more functions per block; content follows the
          common-contract Content rule.
recover : none. qwen3_coder@1 defines no recovery: an unclosed <tool_call> -- whether
          </tool_call>, </function> or </parameter> is missing -- is content whatever
          the finish_reason.
```

**Why these rules.** The Qwen3.5 and Qwen3-Coder templates render a call as
`<tool_call>\n<function=NAME>\n<parameter=KEY>\n` + VALUE + `\n</parameter>\n</function>\n</tool_call>`,
inserting `args_value | string` (or `tojson` for objects and arrays) without escaping.
Removing one LF on each side of VALUE inverts that layout and keeps any newline that
belongs to the value; emitting VALUE as a string keeps arguments a pure function of
committed output; the fixed encoding avoids per-language JSON escaping defaults (Go's
`encoding/json`, for one, escapes `<`, `>` and `&`).

**Reference-engine divergences** (informative). vLLM's Qwen3 XML parser also strips one
LF on each side and keeps VALUE raw, but lets the next `<parameter=` end an unclosed
value, tolerates spaces inside tags, and keeps the last value of a repeated KEY. Dynamo's
`qwen3_coder` trims all whitespace, HTML-unescapes VALUE, coerces it by the tool schema,
and parses a `<function=` even without a `<tool_call>` wrapper. `qwen3_coder@1` takes none
of these leniencies.

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
pointing at this document. Every Go / Rust / TS implementation recomputes every case
in its own CI and asserts byte-identical content / tool_calls; wire's CI checks the
files' bytes and names.

Each vector entry:

```text
{ "name": <case id>,
  "input_utf8": <committed-output string>,
  "finish_reason": <FinishReasonV1 or null>,   // optional; null/absent = pure path.
                                               // only a model-stop value drives recovery.
  "reasoning_parser": <"unsupported@1" or null>, // optional; only for the Support rule.
                                               // `unsupported@1` is a reserved reasoning
                                               // parser that no SDK supports. Cases with a
                                               // real reasoning parser live in that parser's
                                               // reasoning vectors.
  "expected": { "content": <string>, "tool_calls": [ {"name":..., "arguments":...} ] },
  "stream_splits": [ [<byte offsets>], ... ]   // optional; each split must yield expected
}
```

### Required cases: hermes@1

| Class | Case | Expected |
|---|---|---|
| Positive | single block, no surrounding text | content empty, 1 tool_call |
| Positive | Qwen3 layout: `<tool_call>\n{"name": "f", "arguments": {"a": 1}}\n</tool_call>` | content empty, arguments `{"a": 1}` byte for byte |
| Positive | text before + block + text after | content = text before + text after, 1 tool_call |
| Positive | two blocks separated by `\n`, then `\n` at the end | 2 tool_calls in order, content empty (layout dropped) |
| Positive | two blocks with non-whitespace text between them | 2 tool_calls, content = that text verbatim |
| Positive | non-ASCII arguments (e.g. São Paulo) | arguments bytes preserved |
| Positive | arguments with nested objects / arrays and escaped quotes | arguments = raw substring |
| Positive | block with `name` only, no `arguments` key | 1 tool_call, arguments "{}" |
| Positive | extra top-level key besides name / arguments | ignored, 1 tool_call |
| Negative | block whose JSON has no valid `name` | malformed, span as content, 0 tool_calls |
| Positive | `"parameters"` instead of `"arguments"` (not an alias) | key ignored, arguments "{}", 1 tool_call |
| Positive | arguments with a number such as `1e999999` and a duplicate key inside | valid; arguments = raw substring |
| Negative | `"arguments": null` / a string / an array | malformed, span as content |
| Negative | top-level `"name"` twice | malformed, span as content |
| Negative | top-level `"arguments"` twice | malformed, span as content |
| Positive | key written with an escape (`"arguments"`) | matched as `arguments`; arguments = raw value substring |
| Negative | `"name"` and `"name"` both present | `name` twice -> malformed |
| Negative | unpaired surrogate escape `"\ud800"` in a string | malformed, span as content |
| Negative | nesting depth 65 | malformed; depth 64 parses |
| Negative | trailing bytes after the object inside the block | malformed, span as content |
| Negative | string value containing `</tool_call>` | block closes there -> malformed, rest of input follows the Content rule |
| Negative | one good block and one malformed block | 1 tool_call; malformed block's raw bytes in content |
| Negative | orphan `</tool_call>` with no opener | plain text in content |
| Negative | bare JSON `{"name":"f","arguments":{}}` with no markers | content = whole input, 0 tool_calls |
| Negative | no marker at all | content = whole input, 0 tool_calls |
| Negative | `abc<tool_call>…</tool_call></think>ok` (valid closed block), `reasoning_parser` = `unsupported@1` | Support fails -> content = whole input verbatim, 0 tool_calls |
| Negative | start marker, no close, complete JSON; finish_reason null (absent) | buffered span flushed as content, 0 tool_calls |
| Positive | start marker, no close, complete JSON, each of EOS_TOKEN / STOP_SEQUENCE / STOP_TOKEN | recovered as 1 tool_call |
| Negative | start marker, no close, complete JSON, MAX_OUTPUT_TOKENS / MAX_OUTPUT_DURATION / USER_STOP | span as content, 0 tool_calls |
| Negative | start marker, complete JSON, then a trailing partial close marker (`</tool_`), EOS_TOKEN | span as content, 0 tool_calls |
| Negative | start marker, complete JSON followed by a non-whitespace matched stop string (e.g. `END`), STOP_SEQUENCE | span as content, 0 tool_calls |
| Negative | start marker, no close, truncated JSON with surrounding newlines, EOS_TOKEN | span as content byte for byte (untrimmed), 0 tool_calls |
| Negative | `<tool_call>{…}<tool_call>{…}` with no close, EOS_TOKEN | the second `<tool_call>` is payload, invalid JSON -> whole span as content, 0 tool_calls |
| Negative | illegal JSON inside block | block span as content, 0 tool_calls |
| Streaming | JSON split across frames mid-arguments | same final result as non-stream |
| Streaming | split inside `<tool_call>` / `</tool_call>` and inside layout whitespace after a block | same final result |
| Streaming | multi-byte char split on frame boundary | incremental-decode rule holds, concat unchanged |

### Required cases: qwen3_coder@1

| Class | Case | Expected |
|---|---|---|
| Positive | template layout, one parameter | 1 tool_call, VALUE without the wrapping LFs |
| Positive | multiple parameters | arguments members in order of appearance |
| Positive | function with no parameter | arguments "{}" |
| Positive | two functions in one block | 2 tool_calls in order |
| Positive | two blocks separated by `\n` | 2 tool_calls, content empty |
| Positive | VALUE `\n\nx\n\n` (inside the wrapping LFs) | VALUE `\nx\n` |
| Positive | VALUE with leading / trailing spaces and CR | kept verbatim |
| Positive | numeric / boolean-looking VALUE (`42`, `true`) | JSON strings `"42"`, `"true"` |
| Positive | VALUE that is JSON text (object rendered by `tojson`) | kept as one JSON string |
| Positive | VALUE with `<`, `>`, `&`, `&lt;`, `<parameter=`, `</function>` | copied verbatim, no unescaping |
| Positive | VALUE with `"`, `\`, LF, HT, 0x01, 0x7F, U+2028, non-ASCII | encoded per the encoding rule |
| Positive | NAME / KEY with a leading space (`<function= f>`) | kept raw: name ` f` |
| Negative | empty NAME or KEY | malformed, block as content |
| Negative | NAME or KEY containing `<` or LF (`<function=a<b>`) | malformed, block as content |
| Negative | repeated KEY in one function | malformed, block as content |
| Positive | `</parameter>` omitted, a later `</parameter>` follows | VALUE runs on to it, the next `<parameter=…>` included as plain bytes |
| Negative | no `</parameter>` left for an open parameter | malformed, block as content |
| Negative | missing `</function>` before `</tool_call>` | malformed, block as content |
| Negative | non-whitespace text between elements | malformed, block as content |
| Negative | `<parameter = k>` (spaces in tag) | malformed, block as content |
| Negative | `<tool_call>` with no function | malformed, block as content |
| Negative | `<function=f>…</function>` with no `<tool_call>` wrapper | content = whole input, 0 tool_calls |
| Negative | VALUE containing `</tool_call>` | block closes there -> malformed |
| Negative | unclosed block, each finish_reason including EOS_TOKEN | content, 0 tool_calls (no recovery) |
| Streaming | split across `<parameter=…>` and `</parameter>` | same final result |
| Streaming | split between the wrapping LF and VALUE | same final result |

## Open items

1. Governance: `(hermes, 1)` and `(qwen3_coder, 1)` must be in
   `supported_tool_call_parsers` before a profile can pin them.
2. finish_reason is out of scope **except** the verified, model-initiated stop
   finish_reason that gates unclosed-call recovery (common contract / hermes@1). That
   value comes from the signed Fin (verified terminal metadata) -- no new input into
   committed output. transport id / index / type remain out of scope (separate proposal).
