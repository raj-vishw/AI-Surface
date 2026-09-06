package reporting

import "ai-recon-platform/internal/ai"

// RedactSections applies internal/ai.Redact — Phase 13's already-built
// secret-redaction utility, reused rather than re-implemented (phase14.md
// §90: "reuse existing redaction utilities") — to every section's Title
// and Body. Called once at report generation and again at export time
// (internal/service/reporting), the same defense-in-depth two-layer
// redaction discipline internal/ai.ValidateOutput already applies to AI
// provider responses.
func RedactSections(sections Sections) Sections {
	out := make(Sections, len(sections))
	for i, sec := range sections {
		out[i] = Section{Title: ai.Redact(sec.Title), Body: ai.Redact(sec.Body), Citations: sec.Citations}
	}
	return out
}
