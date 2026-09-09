# Control Evidence

This platform makes **no compliance certification claims of any kind**.
`ai-surface control` is a generic, framework-agnostic evidence ledger — an
analyst-populated record linking a security control identifier to a
piece of evidence already collected elsewhere in this platform. Nothing
here computes a compliance percentage, nothing marks a control
"satisfied," and nothing infers control coverage automatically.

## Why no framework is hard-coded

phase14.md §50 is explicit: "do not hard-code a specific compliance
framework unless one already exists in the project." Inspection before
implementing this phase confirmed none does — no SOC 2/ISO 27001/NIST
mapping exists anywhere in this codebase. `ControlEvidence.ControlID` is
therefore a bare, analyst-supplied string (`"AC-2"`, `"encryption-at-
rest"`, or any label an analyst's own framework uses) — this platform
assigns it no meaning beyond a grouping key.

## The model

```go
type ControlEvidence struct {
    ID           uuid.UUID
    TargetID     uuid.UUID
    ControlID    string          // analyst-supplied, no built-in meaning
    EvidenceType EvidenceItemType // finding | alert | detection_match | correlation | investigation | intelligence_record | asset | event
    ReferenceID  uuid.UUID       // the referenced item's own id
    Description  string          // why this evidence relates to the control
    CollectedAt  time.Time       // when the evidence was actually observed
}
```

Recording evidence (`ai-surface control record`) is always an explicit
analyst action — nothing in `internal/service/reporting` calls
`RecordControlEvidence` automatically.

## Evidence sources

`EvidenceType` reuses the exact same reference-type vocabulary
`internal/reporting.EvidenceRef`/`internal/domain/investigation.
EntityType` already use — a control's evidence can point at any finding,
alert, detection match, correlation, investigation, intelligence record,
asset, or (generic) event this platform has ever recorded. A control's
evidence is never copied into `control_evidence` — only a reference plus
a human-written description of why it's relevant, so the evidence's own
record remains the single source of truth.

## The dashboard: evidence, not compliance

`ai-surface control list` (phase14.md §51) shows, per control that has any
recorded evidence at all: how many pieces of evidence exist, and when
the most recently collected one was gathered. **A control nobody has
ever recorded evidence against simply never appears in this list** —
that absence *is* the gap (phase14.md §51's "controls with gaps"),
represented honestly rather than as a fabricated zero-evidence row for
every control name an analyst might expect. No percentage, score, or
"compliant"/"non-compliant" verdict is ever calculated or displayed —
there is no control-mapping framework in this platform to compute one
from, and none is invented.

## Evidence freshness

`ai-surface control list` and the underlying `ControlFreshness` struct
report evidence count and most-recent-collection timestamp only. This
platform defines no expiration policy for control evidence, so **old
evidence is never labeled invalid** (phase14.md §52's own instruction) —
only its age is exposed for an analyst to judge against whatever policy
their own compliance program uses.

## Language

Wherever this platform's output touches control evidence, it uses
language consistent with phase14.md §49's instruction: "evidence
available," "control-related activity observed," "evidence gap" — never
"compliant," "certified," or "passed." If a report or dashboard ever
needs compliance-oriented framing beyond this generic ledger, it must
add its own explicit control-mapping data first; this phase deliberately
stops short of inventing one.
