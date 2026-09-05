package intelligence

import (
	"strconv"
	"time"
)

// AggregatedResult is the read-time, multi-source view over every Record
// known for one indicator (phase10.md §20). It never discards a
// disagreeing source — Records always holds every input record, and
// ConflictingSources reports how many disagreed with the headline
// Verdict (phase10.md §19/§54).
type AggregatedResult struct {
	Indicator Indicator

	Verdict    Verdict
	Confidence Confidence

	SupportingSources  int
	ConflictingSources int

	// Explanation is a short, human-readable statement of how Verdict
	// was reached (phase10.md §20's worked example).
	Explanation string

	Records []Record
}

// SourceWeights optionally weights individual providers' votes in
// Aggregate (phase10.md §21). A provider absent from the map (or a nil
// map) weighs 1.0. Weights are documented multipliers, never presented
// as statistical probabilities (phase10.md §21).
type SourceWeights map[string]float64

// weightOf returns w's weight for providerID, defaulting to 1.0.
func (w SourceWeights) weightOf(providerID string) float64 {
	if w == nil {
		return 1.0
	}
	if v, ok := w[providerID]; ok {
		return v
	}
	return 1.0
}

// Aggregate combines every Record for one indicator into an
// AggregatedResult (phase10.md §19/§20). The headline Verdict is the
// verdict with the greatest total weight among non-unknown verdicts,
// ties broken toward the LESS severe verdict — a deliberate conservative
// default so this platform never headlines "malicious" off a bare tie
// (phase10.md §98: never overclaim). All-unknown (or empty) input
// aggregates to VerdictUnknown.
func Aggregate(records []Record, weights SourceWeights) AggregatedResult {
	if len(records) == 0 {
		return AggregatedResult{Verdict: VerdictUnknown, Confidence: ConfidenceUnknown, Explanation: "no intelligence sources available"}
	}

	byVerdict := map[Verdict]float64{}
	var totalConfidenceRank, knownVerdictCount int
	for _, r := range records {
		if r.Verdict != "" && r.Verdict != VerdictUnknown {
			byVerdict[r.Verdict] += weights.weightOf(r.ProviderID)
		}
		totalConfidenceRank += r.Confidence.Rank()
		knownVerdictCount++
	}

	headline := VerdictUnknown
	bestWeight := 0.0
	for _, v := range []Verdict{VerdictBenign, VerdictSuspicious, VerdictMalicious} {
		w := byVerdict[v]
		if w > bestWeight {
			bestWeight = w
			headline = v
		}
	}

	supporting, conflicting := 0, 0
	for _, r := range records {
		switch {
		case r.Verdict == headline:
			supporting++
		case r.Verdict != "" && r.Verdict != VerdictUnknown:
			conflicting++
		}
	}

	agreement := conflicting == 0 && supporting > 0
	avgConfidenceRank := 0
	if knownVerdictCount > 0 {
		avgConfidenceRank = totalConfidenceRank / knownVerdictCount
	}
	combinedConfidence := ComputeConfidence(
		true, // provider reliability: not separately modeled here, assumed reliable by registration
		true, // freshness: callers should pre-filter to Fresh() records before calling Aggregate
		avgConfidenceRank >= ConfidenceHigh.Rank(),
		agreement,
	)
	// If no provider individually reported high confidence, the
	// aggregate should not silently manufacture it — cap by the best
	// individual confidence observed.
	best := ConfidenceUnknown
	for _, r := range records {
		if r.Confidence.Rank() > best.Rank() {
			best = r.Confidence
		}
	}
	if combinedConfidence.Rank() > best.Rank() {
		combinedConfidence = best
	}

	explanation := explainAggregate(headline, supporting, conflicting, len(records))

	return AggregatedResult{
		Indicator: records[0].Indicator, Verdict: headline, Confidence: combinedConfidence,
		SupportingSources: supporting, ConflictingSources: conflicting,
		Explanation: explanation, Records: records,
	}
}

func explainAggregate(headline Verdict, supporting, conflicting, total int) string {
	base := ""
	switch headline {
	case VerdictUnknown:
		base = "no source reported a definitive verdict"
	default:
		base = "verdict " + string(headline) + " from " + pluralSources(supporting) + " of " + pluralSources(total)
	}
	if conflicting > 0 {
		base += "; " + pluralSources(conflicting) + " disagreed — see individual records"
	}
	return base
}

func pluralSources(n int) string {
	if n == 1 {
		return "1 source"
	}
	return strconv.Itoa(n) + " sources"
}

// FreshRecords filters records to only those still within TTL as of now
// — callers should apply this before Aggregate so stale intelligence
// never silently contributes to a headline verdict (phase10.md §22/§47).
func FreshRecords(records []Record, now time.Time) []Record {
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if r.Fresh(now) {
			out = append(out, r)
		}
	}
	return out
}
