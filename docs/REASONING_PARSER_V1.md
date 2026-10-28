# Reasoning Parser V1

Status: **draft** -- not frozen until the `(name, version)` pair is admitted to
`supported_reasoning_parsers`. See "Open items".

## Scope

This document freezes the **language-neutral behaviour specification** for each
reasoning parser `(name, version)` that a model profile may pin in
`reasoning_parsing.parser`. It is the authority a reviewer checks the shared
vectors in `testdata/v1/parser/` against.

The contract common to every reasoning parser is stated in
"Common contract" below; each parser section then adds only its own markers, start
class and span semantics. Tool-call parsing is a separate document
([Tool Call Parser V1](TOOL_CALL_PARSER_V1.md)); this document covers only the
leading reasoning-span separation that runs **before** it.

## Common contract (all reasoning parsers)

```text
Input    : committed output, UTF-8, already SDK-verified (as in TOOL_CALL_PARSER_V1).
           All positions and matching below are on bytes; markers are ASCII.
Output   : reasoning_content, remainder
           - reasoning_content: the leading reasoning span;
           - remainder: everything after the span's close marker, handed to the
             tool-call parser if pinned, else it is content (text).
           - Semantic order fixed: [reasoning_content] then [content (incl. tool_calls)].
Whitespace: wherever this document says "whitespace" it means exactly the ASCII
           bytes SP (0x20), HT (0x09), LF (0x0A), CR (0x0D). No other byte -- including
           U+FEFF, U+00A0, U+2028 or any other Unicode space -- is whitespace.
Start class: every parser section declares exactly one class for its start marker;
           the same (name, version) never switches class by template, request or
           output content:
           - explicit: the start marker must open the output (after leading
             whitespace). If it does, that leading whitespace and the marker are
             dropped and the span starts right after the marker; any later start
             marker is reasoning text. If it does not -- absent, or any non-whitespace
             byte before it -- there is no reasoning this turn. Reasoning runs from the
             span start to the first close marker. Layout trimming is per parser.
           - implicit: the start marker is taken to sit at offset 0 (the chat template
             put it in the prompt). If, after leading whitespace, the output opens with
             a literal start marker, only that first marker is absorbed, and the
             leading whitespace before it is dropped with it; any later start marker is
             reasoning text. If it does not, nothing is absorbed and leading whitespace
             stays. Reasoning runs from the span start (after the absorbed marker, else
             offset 0) to the first close marker. Layout trimming is per parser.
Internal : tool/call-style markers inside reasoning_content are plain reasoning text --
           they never produce tool_calls, never execute, and never end reasoning. The
           reasoning boundary is the close marker only.
Unclosed : no close marker -> everything from the span start to the end is
           reasoning_content, remainder empty, tool parsing does not run. For an
           implicit parser this includes output with no markers at all.
No marker: explicit parser, no start marker -> no reasoning; the whole committed output
           is the remainder. (Implicit parsers: see Unclosed.)
Unpinned : unsupported (name, version), or manifest unfetchable / hash mismatch
           -> no reasoning; the whole committed output becomes content for the
           tool-call stage. A profile's tool-call parser then counts as unsupported
           too (TOOL_CALL_PARSER_V1, Support), so the whole committed output is
           emitted verbatim as content with 0 tool_calls: a call written while
           reasoning is never parsed.
Streaming: a state machine; the reasoning state machine is chained before the tool
           one (not parallel). Split points -- including inside a marker, inside a
           run of layout bytes a parser trims, or inside a multi-byte character --
           must not change the final concatenated result.
Cross-language: Go / Rust / TS must produce byte-identical reasoning_content /
           content / tool_calls for the same input and (name, version).
```

## Parsers

### qwen3@1

```text
name    : qwen3
version : 1
markers : start = "<think>", end = "</think>"
class   : implicit
span    : 1. Head. Let w = the length of the leading run of whitespace bytes.
             - If the bytes at w begin with "<think>", the span starts at
               w + len("<think>"): that leading whitespace and this one marker are
               dropped (absorbed). Only this first marker is absorbed; a "<think>"
               right after it, or anywhere later, is reasoning text.
             - Otherwise the span starts at 0 and nothing is dropped; leading
               whitespace stays part of the span.
          2. Close. e = the first "</think>" at or after the span start.
             - none -> reasoning_content = bytes [span start, end); remainder empty;
               tool parsing does not run.
             - found -> reasoning_content = bytes [span start, e);
               remainder = bytes after that "</think>".
          3. Layout. Remove every consecutive LF (0x0A) at the start and at the end of
             reasoning_content, and every consecutive LF at the start of the remainder.
             Only LF is removed; CR, SP and HT are kept.
          The remainder is otherwise untouched: a later "<think>" or "</think>" in it is
          plain text for the tool-call stage / content.
```

**Why implicit.** A profile's chat template is pinned by `chat_template_hash` and a
request carries no thinking switch, so only the template's default branch runs. Both
Qwen template families default to thinking, and in both the committed output opens
with reasoning:

| Template (default branch) | Generation prompt ends with | Committed output |
|---|---|---|
| Qwen3 (e.g. Qwen3-8B) | `<\|im_start\|>assistant\n` | `<think>\n…\n</think>\n\n…` (model writes `<think>`) |
| Qwen3.5 (e.g. Qwen3.5-9B) | `<\|im_start\|>assistant\n<think>\n` | `…\n</think>\n\n…` (`<think>` is in the prompt) |

Absorbing a head `<think>` makes both yield the same split. The layout rule mirrors
how the templates render an assistant turn,
`'<think>\n' + reasoning.strip('\n') + '\n</think>\n\n' + content.lstrip('\n')`.
A turn with thinking switched off by the model (e.g. the Qwen3 `/no_think` soft
switch) writes an empty `<think>\n\n</think>\n\n` pair, which gives empty
reasoning_content.

**Applicability.** Pin `qwen3@1` only on a profile whose pinned template defaults to
thinking. A profile whose template does not think by default (Instruct / Coder models,
or a template whose default turns thinking off) pins no reasoning parser
(`reasoning_parsing {}`); pinning `qwen3@1` there would turn the
whole answer into reasoning.

**Worked examples** (`\n` is LF, `\r` is CR, `\uFEFF` is the BOM; all are vectors):

| Input | reasoning_content | content (no tool parser) |
|---|---|---|
| `<think>\nabc\n</think>\n\nok` | `abc` | `ok` |
| `abc\n</think>\n\nok` | `abc` | `ok` |
| `<think>\n\n</think>\n\nok` | (empty) | `ok` |
| `abc` (no markers) | `abc` | (empty), no tool parse |
| `<think>\nabc` (unclosed) | `abc` | (empty), no tool parse |
| `abc<think>x</think>ok` | `abc<think>x` | `ok` |
| `<think><think>abc</think>ok` | `<think>abc` | `ok` |
| `  <think>abc</think>ok` | `abc` | `ok` |
| `  abc</think>ok` | `  abc` | `ok` |
| `\n\nabc</think>ok` | `abc` | `ok` |
| `\uFEFF<think>abc</think>ok` | `\uFEFF<think>abc` | `ok` |
| `<think>\r\nabc\r\n</think>\r\nok` | `\r\nabc\r` | `\r\nok` |
| `<think>a</think>b</think>c` | `a` | `b</think>c` |

**Reference-engine divergences** (informative). vLLM's `qwen3` parser ends reasoning
implicitly at a `<tool_call>` and drops every `<think>` seen while reasoning; Dynamo
extracts `<think>…</think>` pairs found anywhere and, unless the prompt ends with
`<think>`, starts outside reasoning. `qwen3@1` deliberately keeps the close marker as
the only boundary and absorbs only the head marker, so outputs such as
`abc<think>x</think>ok` or a `<tool_call>` inside unclosed reasoning split differently
from those engines.

## Shared vector file

Path: `testdata/v1/parser/reasoning_qwen3_v1.json`, registered in
`testdata/v1/manifest.json` with `"origin": "wire"` and a `contract_section`
pointing here. CI recomputes every case in Go / Rust / TS and asserts
byte-identical output.

Each vector entry:

```text
{ "name": <case id>,
  "input_utf8": <committed-output string>,
  "tool_call_parser": <name@version or null>,   // for combination cases
  "finish_reason": <FinishReasonV1 or null>,    // optional; as in TOOL_CALL_PARSER_V1,
                                                // only for the tool stage's recovery gate
  "expected": { "reasoning_content": <string>, "content": <string>,
                "tool_calls": [ {"name":..., "arguments":...} ] },
  "stream_splits": [ [<byte offsets>], ... ]      // optional
}
```

### Required cases

Every row of the worked-examples table above, plus:

| Class | Case | Expected |
|---|---|---|
| Combination | tool-style marker inside closed reasoning | stays reasoning text, 0 tool_calls |
| Combination | `<tool_call>` inside unclosed reasoning (no `</think>`) | all reasoning_content, 0 tool_calls, no tool parse |
| Combination | `<tool_call>` inside reasoning with no markers at all | all reasoning_content, 0 tool_calls, no tool parse |
| Combination | `<think>…</think><tool_call>…</tool_call>` | reasoning_content + 1 tool_call, content empty |
| Combination | `…</think>` then text, then a tool call | reasoning + content + tool_calls, order fixed |
| Combination | `…</think><tool_call>` + complete JSON, no `</tool_call>`, hermes@1, EOS_TOKEN | reasoning_content + 1 recovered tool_call |
| Combination | same, MAX_OUTPUT_TOKENS | reasoning_content, the open block as content, 0 tool_calls |
| Combination | `<tool_call>` + complete JSON inside unclosed reasoning, hermes@1, EOS_TOKEN | all reasoning_content, 0 tool_calls, no tool parse (finish_reason does not reach reasoning) || Streaming | split inside `<think>` and inside `</think>` | same final result |
| Streaming | split inside the leading whitespace run and inside the LF runs trimmed by the layout rule | same final result |
| Streaming | multi-byte character split across frames | same final result |

## Open items

1. Governance: `(qwen3, 1)` must be in `supported_reasoning_parsers` before a
   profile can pin it.
