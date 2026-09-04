package detection

// MergeFindings collapses findings sharing the same engine-side
// IdentityKey into one, unioning Evidence and References, taking the
// maximum Confidence, and keeping the highest-ranked Severity
// (phase8.md §43/§44). This is a safety net, not the primary
// deduplication mechanism: internal/service/detection already hands each
// Detector one already-multi-source-merged observation per endpoint
// (Phase 7's own accumulator merged HTML/JS/OpenAPI/robots/sitemap
// evidence into a single Endpoint row upstream), so a well-behaved
// detector normally emits at most one Finding per identity already; this
// only guards against a detector that, by construction or a future bug,
// returns more than one for the same (asset, endpoint, detector) triple.
func MergeFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}

	order := make([]string, 0, len(findings))
	byKey := make(map[string]Finding, len(findings))
	for _, f := range findings {
		key := f.IdentityKey()
		existing, ok := byKey[key]
		if !ok {
			byKey[key] = f
			order = append(order, key)
			continue
		}
		byKey[key] = mergeInto(existing, f)
	}

	merged := make([]Finding, 0, len(order))
	for _, key := range order {
		merged = append(merged, byKey[key])
	}
	return merged
}

func mergeInto(existing, add Finding) Finding {
	if add.Confidence > existing.Confidence {
		existing.Confidence = add.Confidence
	}
	if add.Severity.Rank() > existing.Severity.Rank() {
		existing.Severity = add.Severity
	}
	existing.Evidence = append(existing.Evidence, add.Evidence...)
	existing.References = mergeReferences(existing.References, add.References)
	if existing.Metadata == nil && add.Metadata != nil {
		existing.Metadata = add.Metadata
	}
	return existing
}

func mergeReferences(existing, add []Reference) []Reference {
	seen := make(map[string]bool, len(existing))
	for _, r := range existing {
		seen[r.Label+"|"+r.URL] = true
	}
	for _, r := range add {
		key := r.Label + "|" + r.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		existing = append(existing, r)
	}
	return existing
}
