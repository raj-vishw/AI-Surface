# AI Investigation Guide

This guide walks through what the AI assistant can do and how to invoke
it. Every output is advisory — reviewed and, where relevant, explicitly
approved by an analyst before it becomes part of an investigation's
official record (see `docs/ai/safety.md`).

## Enabling the assistant

Disabled by default. Enable it in configuration:

```yaml
ai:
  enabled: true
  provider:
    name: mock # or "openai" — see below
```

Check status:

```sh
ai-surface ai status
```

## Summarize an investigation

```sh
ai-surface ai summarize <investigation-id> --actor analyst1
```

Produces an executive summary, per-item observations (each cited), an
`Unknown` section (always present — phase13.md §16), evidence gaps
relative to a standard coverage checklist, and suggested next steps.

## Analyze a timeline

```sh
ai-surface ai analyze <investigation-id> --actor analyst1
```

A chronological account of the investigation's evidence, flagging the
largest gap between consecutive items — never claiming to know what
happened during a gap, only that one exists.

## Generate investigation questions

```sh
ai-surface ai questions <investigation-id> --actor analyst1
```

Questions are always tied to an actual evidence gap or an actual
present-but-unexplored signal — e.g. "Which asset was affected?" only
appears when no asset context is attached yet.

## Draft a report

```sh
ai-surface ai report <investigation-id> --actor analyst1 --save-as-note
```

Combines the summary and questions into one draft. `--save-as-note` saves
the result as an AI-generated investigation note (`AIGenerated = true`,
unapproved) — approve it explicitly once reviewed:

```sh
ai-surface ai note approve <note-id> --approver analyst1
```

## Explain an alert

```sh
ai-surface ai explain-alert <alert-id> --actor analyst1
```

Explains what triggered the alert (its underlying detection match and
rule, when available), severity/confidence, and limitations. Never
changes the alert's own severity or status.

## Explain a detection match

```sh
ai-surface ai explain-detection <detection-match-id> --actor analyst1
```

Explains the rule, its version, and the match's own recorded explanation
— always including a false-positive-consideration line.

## Analyze a correlation or attack chain

```sh
ai-surface ai analyze-correlation <correlation-id> --actor analyst1
ai-surface ai analyze-correlation <correlation-id> --actor analyst1 --chain
```

Without `--chain`: explains why the underlying evidence was grouped
(shared entities, temporal/detection relationships, intelligence
context). With `--chain`: walks the attack chain's stages in order —
absent stages are gaps, never invented (mirrors `internal/correlation`'s
own chain-building discipline exactly).

## Sessions and follow-up questions

Open a session (optionally scoped to one investigation) to ask follow-up
questions with preserved context:

```sh
ai-surface ai session new --investigation <id> --actor analyst1
ai-surface ai chat <session-id> "What evidence is missing?"
ai-surface ai session show <session-id>
ai-surface ai session clear <session-id>   # wipes messages, keeps the session and all investigation data
ai-surface ai session delete <session-id>  # deletes the session entirely
```

## Reading the output

Every response ends with a fixed banner:

```
[AI-generated — advisory only, requires analyst review. Not a confirmed finding.]
```

and reports its own `AI Confidence` — a measure of how well-grounded the
interpretation is, never a probability that an attack occurred (see
`docs/ai/safety.md`).

## Using a real provider

```yaml
ai:
  provider:
    name: openai
    model: gpt-4o-mini
    endpoint: https://api.openai.com/v1/chat/completions
    api_key_env: OPENAI_API_KEY
```

Set `OPENAI_API_KEY` in the environment — never in configuration. The
platform remains fully usable with `provider.name: mock` and no external
dependency at all; every task above works identically either way, since
the structured facts are built the same way regardless of provider.
