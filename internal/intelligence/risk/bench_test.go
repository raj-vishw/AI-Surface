package risk

import "testing"

// BenchmarkScorer_Calculate_50000 benchmarks risk calculation at a scale
// roughly comparable to 50,000 findings' worth of independent scoring
// calls (phase10.md §92).
func BenchmarkScorer_Calculate_50000(b *testing.B) {
	s := NewScorer(DefaultWeights())
	inputs := make([]Input, 50000)
	severities := []Severity{SeverityInformational, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := range inputs {
		inputs[i] = Input{
			HighestFindingSeverity:     severities[i%len(severities)],
			InternetFacing:             i%2 == 0,
			OpenServiceCount:           i % 10,
			HighestVulnerabilityStatus: VulnerabilityProbable,
			AssetCriticality:           CriticalityNormal,
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Calculate(inputs[i%len(inputs)])
	}
}
