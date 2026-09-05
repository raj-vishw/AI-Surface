package intelligence

import (
	"context"
	"fmt"
	"testing"
)

// BenchmarkNormalize_10000Indicators benchmarks indicator normalization
// at scale (phase10.md §92).
func BenchmarkNormalize_10000Indicators(b *testing.B) {
	indicators := make([]Indicator, 10000)
	for i := range indicators {
		indicators[i] = Indicator{Type: IndicatorDomain, Value: fmt.Sprintf("HOST-%d.EXAMPLE.com.", i)}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ind := range indicators {
			_ = Normalize(ind)
		}
	}
}

// BenchmarkMemoryCache_10000Lookups benchmarks cache Get/Set at scale.
func BenchmarkMemoryCache_10000Lookups(b *testing.B) {
	cache := NewMemoryCache()
	ctx := context.Background()
	keys := make([]CacheKey, 10000)
	for i := range keys {
		keys[i] = CacheKey{ProviderID: "local", Indicator: Indicator{Type: IndicatorDomain, Value: fmt.Sprintf("host-%d.example.com", i)}}
		_ = cache.Set(ctx, keys[i], []Record{{ProviderID: "local"}}, 0)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = cache.Get(ctx, keys[i%len(keys)])
	}
}

// BenchmarkAggregate_10000Records benchmarks multi-source aggregation at
// scale.
func BenchmarkAggregate_10000Records(b *testing.B) {
	records := make([]Record, 10000)
	verdicts := []Verdict{VerdictBenign, VerdictSuspicious, VerdictMalicious, VerdictUnknown}
	for i := range records {
		records[i] = Record{ProviderID: fmt.Sprintf("p%d", i%20), Verdict: verdicts[i%len(verdicts)], Confidence: ConfidenceMedium}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Aggregate(records, nil)
	}
}

// BenchmarkMatcher_10000VulnerabilityRecords benchmarks vulnerability
// matching against a large catalog (phase10.md §92's "at least 10,000
// vulnerability records").
func BenchmarkMatcher_10000VulnerabilityRecords(b *testing.B) {
	catalog := make([]CatalogEntry, 10000)
	for i := range catalog {
		catalog[i] = CatalogEntry{
			ID: fmt.Sprintf("v%d", i), Identifier: fmt.Sprintf("CVE-2024-%05d", i),
			AffectedProduct: "nginx", VersionConstraints: []string{"<1.21.0"},
		}
	}
	matcher := NewMatcher(catalog)
	obs := TechnologyObservation{Product: "nginx", Version: "1.18.0"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matcher.Evaluate(obs)
	}
}

// BenchmarkEngine_Lookup_50000Findings benchmarks the engine's per-
// indicator provider fan-out at a scale roughly comparable to 50,000
// findings' worth of distinct assets being enriched one indicator at a
// time (phase10.md §92) — synthetic data only, no real network access.
func BenchmarkEngine_Lookup_50000Findings(b *testing.B) {
	r := NewRegistry()
	_ = r.Register(stubProvider{id: "local", records: []Record{{ProviderID: "local", Verdict: VerdictUnknown, Confidence: ConfidenceHigh}}})
	e := NewEngine(r)
	cache := NewMemoryCache()
	ctx := context.Background()

	indicators := make([]Indicator, 50000)
	for i := range indicators {
		indicators[i] = Indicator{Type: IndicatorDomain, Value: fmt.Sprintf("host-%d.example.com", i)}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Lookup(ctx, indicators[i%len(indicators)], Config{}, cache)
	}
}
