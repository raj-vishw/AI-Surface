package intelligence

// ComputeConfidence derives a leveled Confidence from the four factors
// phase10.md §55 names: provider reliability, source freshness, an exact
// (vs fuzzy) indicator match, and agreement between providers. Each
// factor contributes 0 or 1 point (documented, not a hidden formula);
// the total (0-4) maps onto the four Confidence levels. This is a
// deliberately simple, explainable point count — not a claim of
// statistical calibration (phase10.md §55).
func ComputeConfidence(reliable, fresh, exactMatch, agreement bool) Confidence {
	points := 0
	for _, ok := range []bool{reliable, fresh, exactMatch, agreement} {
		if ok {
			points++
		}
	}
	switch {
	case points >= 3:
		return ConfidenceHigh
	case points == 2:
		return ConfidenceMedium
	case points == 1:
		return ConfidenceLow
	default:
		return ConfidenceUnknown
	}
}
