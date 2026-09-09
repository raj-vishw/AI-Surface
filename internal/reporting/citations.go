package reporting

import (
	"time"

	"ai-surface-platform/internal/ai"
)

// EvidenceRef is one piece of evidence a report may cite — the exact
// same "[type:id]" bracketed token convention Phase 13's internal/ai
// package already established (ai.Fact.Citation), reused here rather
// than inventing a second citation syntax. Timestamp is the underlying
// item's own observation time (never the report's generation time) —
// carried through from wherever the reference was first resolved so
// internal/service/reporting's evidence-package builder never has to
// re-query it a second time.
type EvidenceRef struct {
	Type      string    `json:"type"`
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
}

// Token returns ref's citation token, e.g. "[finding:3fae...]".
func (ref EvidenceRef) Token() string {
	return ai.Fact{Type: ai.FactType(ref.Type), ID: ref.ID}.Citation()
}

// citationSet builds the allowlist ValidateSections checks every section
// against.
func citationSet(refs []EvidenceRef) map[string]bool {
	set := make(map[string]bool, len(refs))
	for _, r := range refs {
		set[r.Token()] = true
	}
	return set
}

// ValidateSections implements phase14.md §37/§92: every citation a
// section's Body makes is checked against refs (the report's own
// evidence list); a citation not present there is stripped from the
// text and removed from the section's own Citations list — a fabricated
// evidence reference never survives into a final report, reusing
// internal/ai's own citation-validation logic (ai.ValidateCitations)
// rather than a second implementation. Returns the cleaned sections plus
// every token that had to be removed, for audit/logging.
func ValidateSections(sections Sections, refs []EvidenceRef) (Sections, []string) {
	valid := citationSet(refs)
	var allRemoved []string
	cleaned := make(Sections, len(sections))
	for i, sec := range sections {
		body, removed := ai.ValidateCitations(sec.Body, valid)
		allRemoved = append(allRemoved, removed...)

		var keptCitations []string
		for _, c := range sec.Citations {
			if valid[c] {
				keptCitations = append(keptCitations, c)
			}
		}
		cleaned[i] = Section{Title: sec.Title, Body: body, Citations: keptCitations}
	}
	return cleaned, allRemoved
}
