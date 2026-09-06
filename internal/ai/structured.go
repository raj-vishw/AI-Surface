package ai

import "strings"

// StructuredResult is this engine's internal, structured representation
// of one task's output (phase13.md §39: "prefer structured output
// internally... do not rely entirely on free-form parsing"). It is built
// deterministically from a Context by the functions in investigator.go —
// never by parsing a provider's free-form text — so the
// Observed/Inferred/Unknown/EvidenceGaps/NextSteps/Citations sections are
// always grounded in real Fact values regardless of which Provider (mock
// or real) ultimately narrates them.
type StructuredResult struct {
	Summary string

	// Observed states only what the platform's own records directly show
	// (phase13.md §16) — one line per statement, each ending with its
	// supporting citation(s).
	Observed []string
	// Inferred states a relationship or interpretation this engine (or the
	// correlation engine whose edges it read) derived, never asserted as
	// fact (phase13.md §16).
	Inferred []string
	// Unknown lists what the available evidence does not establish —
	// always present, never omitted merely because nothing came to mind
	// (phase13.md §16's worked example: "Unknown: Whether the credentials
	// were compromised.").
	Unknown []string

	EvidenceGaps []string
	NextSteps    []string
	Questions    []string

	// Citations is the deduplicated set of every citation token used
	// anywhere above, in first-appearance order.
	Citations []string
}

// addCitation appends token to r.Citations if not already present.
func (r *StructuredResult) addCitation(token string) {
	for _, c := range r.Citations {
		if c == token {
			return
		}
	}
	r.Citations = append(r.Citations, token)
}

// observe appends a statement plus its citation to Observed, and records
// the citation.
func (r *StructuredResult) observe(statement string, cite string) {
	r.Observed = append(r.Observed, statement+" "+cite)
	r.addCitation(cite)
}

// infer appends a statement plus its citation(s) to Inferred.
func (r *StructuredResult) infer(statement string, cites ...string) {
	line := statement
	for _, c := range cites {
		line += " " + c
		r.addCitation(c)
	}
	r.Inferred = append(r.Inferred, line)
}

// Render renders r into the final section-headed text form every task's
// output takes (phase13.md §84's own worked CLI example follows exactly
// this shape). This is what MockProvider narrates verbatim, and what
// Assistant falls back to verbatim if a real provider's own narration
// fails citation validation.
func (r StructuredResult) Render() string {
	var b strings.Builder
	writeSection := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		b.WriteString(title)
		b.WriteString(":\n")
		for _, l := range lines {
			b.WriteString("  - ")
			b.WriteString(l)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if r.Summary != "" {
		b.WriteString("Summary:\n  ")
		b.WriteString(r.Summary)
		b.WriteString("\n\n")
	}
	writeSection("Observed", r.Observed)
	writeSection("Inferred", r.Inferred)
	writeSection("Unknown", r.Unknown)
	writeSection("Evidence Gaps", r.EvidenceGaps)
	writeSection("Recommended Next Steps", r.NextSteps)
	writeSection("Investigation Questions", r.Questions)

	if len(r.Citations) > 0 {
		b.WriteString("Sources:\n")
		for _, c := range r.Citations {
			b.WriteString("  ")
			b.WriteString(c)
			b.WriteString("\n")
		}
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}
