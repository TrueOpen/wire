# Reasoning Parser V1

Status: **draft** -- the `qwen3@1` markers are grounded in the Qwen `<think>`
convention but are not frozen until (a) reviewed against the pinned engine and
(b) the `(name, version)` pair is admitted to `supported_reasoning_parsers`.
See "Open items".

## Scope

This document freezes the **language-neutral behaviour specification** for each
reasoning parser `(name, version)` that a model profile may pin in
`reasoning_parsing.parser`. It is the authority a reviewer checks the shared
vectors in `testdata/v1/parser/` against.

The contract common to every reasoning parser is stated in "Common contract"
below; each parser section then adds only its own markers and span semantics.
Tool-call parsing is a separate document
([Tool Call Parser V1](TOOL_CALL_PARSER_V1.md)); this document covers only the
leading reasoning-span separation that runs **before** it.

## Common contract (all reasoning parsers)

```text
Input    : committed output, UTF-8, already SDK-verified (as in TOOL_CALL_PARSER_V1).
Output   : reasoning_content, remainder
           - reasoning_content: the leading reasoning span (bounded by the markers);
           - remainder: everything after, handed to the tool-call parser if pinned,
             else it is content (text).
           - Semantic order fixed: [reasoning_content] then [content (incl. tool_calls)].
Lead     : reasoning must be at the very start. If the start marker is in the committed
           output, any non-whitespace byte before it means "no reasoning this turn". If
           the parser spec declares the start marker injected into the prompt (absent
           from committed output), reasoning leads from byte 0 to the close marker.
Internal : tool/call-style markers inside reasoning_content are plain reasoning text --
           they never produce tool_calls and never execute.
Unclosed : start marker (or byte 0, when the start marker is prompt-injected), no close
           (e.g. max_tokens cut) -> everything from there to end is reasoning_content,
           content empty, tool parsing does not run.
Unpinned : unsupported (name, version), or manifest unfetchable / hash mismatch
           -> no reasoning; the whole committed output becomes content for the
           tool-call stage.
Streaming: a state machine; the reasoning state machine is chained before the tool
           one (not parallel). Split points must not change the final concatenated
           result.
Cross-language: Go / Rust / TS must produce byte-identical reasoning_content /
           content / tool_calls for the same input and (name, version).
```

## Parsers

### qwen3@1

```text
name    : qwen3
version : 1
markers : start = "<think>" (may be absent, see below), end = "</think>"
span    : reasoning_content = bytes from the start of committed output up to the
          first "</think>"; if a leading "<think>" is present it is excluded.
          remainder = bytes after "</think>".
```

**Start marker may live in the prompt, not the committed output.** Two template
families produce different committed output for the same reasoning:

- older Qwen3 templates (up to the 2507 release): the model generates
  `<think>...</think>`, so the committed output contains the full pair.
- Qwen3.5+ templates: `<think>` is injected into the *prompt*, so only `</think>`
  appears in the committed output; reasoning then leads from byte 0.

Both must yield the same `reasoning_content` = everything before `</think>`. This
is why the span is defined by the `</think>` close marker, not by a required
leading `<think>`.

> **Interaction with the reasoning-must-lead rule.** A parser may declare its start
> marker injected into the prompt (absent from the committed output); reasoning then
> leads from byte 0 to the first `</think>`, and "reasoning must lead" is read as "leads
> from byte 0". qwen3@1's Qwen3.5+ mode pins exactly that case; the invariant still holds.

> **TBD before freeze**: exact whitespace trimming of reasoning_content and
> remainder; whether "disabled thinking" (an empty `<think>\n\n</think>` prefix)
> appears in committed output or only in the prompt. Resolve against the pinned
> engine, then remove this note.

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
  "expected": { "reasoning_content": <string>, "content": <string>,
                "tool_calls": [ {"name":..., "arguments":...} ] },
  "stream_splits": [ [<byte offsets>], ... ]      // optional
}
```

### Required cases

| Class | Case | Expected |
|---|---|---|
| Positive | `<think>...</think>` then plain text, no tool parser | reasoning_content set, content = remainder |
| Positive | only trailing `</think>` (Qwen3.5+, `<think>` in prompt) | reasoning_content = from byte 0, content = remainder |
| Positive | reasoning then text, tool parser pinned, tool in remainder | reasoning + content + tool_calls, order fixed |
| Negative | no markers | reasoning_content empty, content = whole input |
| Negative | non-whitespace before `<think>` | no reasoning, whole input is content |
| Negative | `<think>` unclosed (truncation) | all-from-start is reasoning_content, content empty, no tool parse |
| Combination | tool-style marker inside reasoning (closed think) | stays reasoning text, 0 tool_calls |
| Combination | `<tool_call>` inside an unclosed think block (no `</think>`) | all reasoning_content, 0 tool_calls, no tool parse |
| Combination | reasoning + tool: `<think>...</think><tool_call>...</tool_call>` | reasoning_content + 1 tool_call, content empty |
| Streaming | reasoning span split across frames | same final result |
| Streaming | multi-byte char on `</think>` boundary | incremental-decode rule holds |

## Open items

0. **Protocol clarifications** (found while verifying against vLLM's `qwen3`
   reasoning parser). Both were protocol decisions, now **resolved in the governing
   protocol spec** and frozen in the common contract above; recorded here so the vectors
   trace to the decision.
   - *Start marker absent (Qwen3.5+ emits only `</think>`)* -- **resolved**: when a
     parser declares the start marker injected into the prompt, reasoning leads from
     byte 0 to the first `</think>` (see the span definition and interaction note
     above). The unclosed fallback matches (no close marker -> all reasoning); the
     "disabled thinking" no-marker encoding is deferred to this parser spec (see TBD).
   - *`<tool_call>` inside an unclosed think block* -- **resolved**: the strict reading
     is frozen. The reasoning boundary is the close marker only; a `<tool_call>` inside
     reasoning stays text and does not end reasoning; an unclosed think block is all
     reasoning, no tool parse. Deliberate, safe-side divergence from vLLM's
     implicit-end-of-reasoning behaviour -- a call not sealed by a normal `</think>` is
     not executed; emitting one is engine/template malformation, not an SDK guess.
1. Freeze `qwen3@1` markers/whitespace against the pinned engine; remove the TBD.
2. Governance: `(qwen3, 1)` must be in `supported_reasoning_parsers` before a
   profile can pin it.
