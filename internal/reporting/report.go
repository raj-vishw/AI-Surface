// Package reporting implements Phase 14's report-building engine: it
// assembles already-fetched data (analytics results, evidence
// references) into a report's Sections, validates every citation those
// sections make, and renders the result to JSON or CSV — never a second
// PDF/HTML system (phase14.md §42: "use the existing PDF/export
// infrastructure if already present" — none exists in this codebase, so
// human-readable rendering here means the same structured JSON/CSV every
// other export in this platform already produces).
//
// Like internal/analytics, this package is not a zero-dependency
// "engine" in the internal/correlation sense — it deliberately reuses
// internal/ai's already-built citation-validation and redaction
// utilities (phase14.md §90's "reuse existing redaction utilities",
// §92's "validate citations... do not allow fabricated evidence
// references") rather than re-implementing either.
package reporting

import (
	"sort"
	"strings"
)

// Section is one named part of a report's content (phase14.md §33-36's
// per-type section lists). Body is plain text — this platform renders no
// HTML anywhere, so there is no markup for untrusted content to be
// injected into (see docs/reporting/reports.md's "Content Security"
// section for the full reasoning).
type Section struct {
	Title string
	Body  string
	// Citations is the deduplicated set of every [type:id] evidence
	// reference this section's Body actually cites, in first-appearance
	// order — validated against the report's own EvidenceRefs before the
	// report is ever persisted (see ValidateSections).
	Citations []string
}

// Sections is one report's full content.
type Sections []Section

// Render renders every section as a simple, human-readable text block —
// used for the CLI's own `report show` output and as the deterministic
// fallback if richer rendering is ever added later.
func (s Sections) Render() string {
	var b strings.Builder
	for _, sec := range s {
		b.WriteString(sec.Title)
		b.WriteString("\n")
		b.WriteString(strings.Repeat("-", len(sec.Title)))
		b.WriteString("\n")
		b.WriteString(sec.Body)
		b.WriteString("\n\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// AllCitations returns every citation used anywhere in s, deduplicated,
// sorted — the report's own complete evidence-reference list
// (phase14.md §37/§44's "evidence references").
func (s Sections) AllCitations() []string {
	seen := make(map[string]bool)
	var out []string
	for _, sec := range s {
		for _, c := range sec.Citations {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}
