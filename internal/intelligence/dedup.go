package intelligence

// recordKey is the identity a duplicate Record shares — the same
// provider reporting the same verdict/confidence/source-reference for
// the same indicator within one lookup. Two records that genuinely
// disagree (different verdict) are never deduplicated — see
// internal/domain/intelligence's "preserve history" requirement
// (phase10.md §47) and Aggregate's "preserve conflict" requirement
// (phase10.md §54).
type recordKey struct {
	provider, indicator, verdict, confidence, sourceRef string
}

func keyOf(r Record) recordKey {
	return recordKey{
		provider: r.ProviderID, indicator: r.Indicator.Key(),
		verdict: string(r.Verdict), confidence: string(r.Confidence), sourceRef: r.SourceReference,
	}
}

// DedupRecords removes exact duplicates from records — the same
// provider, indicator, verdict, confidence, and source reference —
// keeping the one with the most recent RetrievedAt. This never merges
// records that disagree (phase10.md §19/§54).
func DedupRecords(records []Record) []Record {
	if len(records) <= 1 {
		return records
	}
	best := make(map[recordKey]Record, len(records))
	order := make([]recordKey, 0, len(records))
	for _, r := range records {
		k := keyOf(r)
		existing, ok := best[k]
		if !ok {
			order = append(order, k)
			best[k] = r
			continue
		}
		if r.RetrievedAt.After(existing.RetrievedAt) {
			best[k] = r
		}
	}
	out := make([]Record, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}
