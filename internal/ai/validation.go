package ai

import "strings"

// ValidationOutcome is what happened when a provider's raw narration was
// checked before being shown to an analyst (phase13.md §38).
type ValidationOutcome struct {
	Content string

	FabricatedCitationsRemoved []string
	UnsupportedClaimsRewritten int
	// AttributionRejected is true when the raw content asserted
	// threat-actor attribution (phase13.md §18) — such content is never
	// merely rewritten; the entire narration is discarded in favor of the
	// deterministic StructuredResult.Render() fallback, because attribution
	// is out of scope regardless of phrasing.
	AttributionRejected bool
	// UsedFallback is true when Content was replaced entirely by the
	// deterministic structured rendering (attribution found, or citation
	// validation stripped so much that the narration would open with
	// nothing left).
	UsedFallback bool
}

// ValidateOutput applies every output-safety check phase13.md §38 lists —
// citations, unsupported claims, attribution, sensitive-information
// leakage (redaction was already applied before the prompt was built, so
// nothing new can appear here that wasn't already in the context; this
// pass exists for defense in depth against a provider echoing something
// it was told not to) — to one provider's raw narration, falling back to
// fallback (typically structured.Render()) when the content cannot be
// made safe by rewriting.
func ValidateOutput(raw string, validCitations map[string]bool, fallback string) ValidationOutcome {
	out := ValidationOutcome{}

	if ContainsAttribution(raw) {
		out.AttributionRejected = true
		out.Content = fallback
		out.UsedFallback = true
		return out
	}

	cleaned, removed := ValidateCitations(raw, validCitations)
	out.FabricatedCitationsRemoved = removed

	cleaned = Redact(cleaned) // defense in depth — see doc comment above

	rewritten, count := RewriteUnsupportedClaims(cleaned)
	out.UnsupportedClaimsRewritten = count

	if strings.TrimSpace(rewritten) == "" {
		out.Content = fallback
		out.UsedFallback = true
		return out
	}

	out.Content = rewritten
	return out
}
