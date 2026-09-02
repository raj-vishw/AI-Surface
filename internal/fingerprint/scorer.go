package fingerprint

// score computes a signature's confidence from its matched (deduplicated)
// signals, per phase6.md §8's worked model:
//
//	score = weighted evidence / maximum possible evidence
//
// "Maximum possible evidence" is the sum of every *declared* signal's
// weight in the signature (not just the matched ones) — so a signature
// with five declared signals that only matches one weak one scores lower
// than a signature with two declared signals that both match, even if
// the single matched weight is numerically larger. This is what makes
// corroboration (phase6.md §9) fall out naturally: more independent
// signals matching (never double-counting a duplicate — matchSignature
// already deduplicated before this is called) monotonically raises the
// score, and it can never exceed 1.0 by construction (matched weight is
// always <= declared weight).
func score(matched []Signal, declared []compiledSignal) float64 {
	if len(declared) == 0 {
		return 0
	}
	var total, achieved float64
	for _, d := range declared {
		total += d.rule.Weight
	}
	seen := make(map[string]bool, len(matched))
	for _, s := range matched {
		if seen[s.key()] {
			continue // defense in depth — matchSignature already dedupes
		}
		seen[s.key()] = true
		achieved += s.Weight
	}
	if total <= 0 {
		return 0
	}
	result := achieved / total
	if result > 1 {
		result = 1
	}
	if result < 0 {
		result = 0
	}
	return result
}
