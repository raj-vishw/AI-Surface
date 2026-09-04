package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

// syntheticFindings builds n findings spread across n/5 assets — enough
// same-asset pairs to exercise sameAssetRule's O(n^2)-per-run pairwise
// scan realistically (phase9.md §76's synthetic-dataset benchmark
// requirement).
func syntheticFindings(n int) investigation.Input {
	in := investigation.Input{Assets: map[uuid.UUID]investigation.AssetObservation{}}
	assetIDs := make([]uuid.UUID, 0, n/5+1)
	for i := 0; i < n/5+1; i++ {
		id := uuid.New()
		assetIDs = append(assetIDs, id)
		in.Assets[id] = investigation.AssetObservation{ID: id, Hostname: "asset.test"}
	}
	now := time.Now()
	for i := 0; i < n; i++ {
		in.Findings = append(in.Findings, investigation.FindingObservation{
			ID: uuid.New(), AssetID: assetIDs[i%len(assetIDs)], Category: "configuration", FirstSeen: now,
		})
	}
	return in
}

func BenchmarkSameAssetRule_1000Findings(b *testing.B) {
	input := syntheticFindings(1000)
	rule := sameAssetRule{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rule.Evaluate(context.Background(), input)
	}
}

func BenchmarkFullRegistry_1000Findings(b *testing.B) {
	registry := investigation.NewRegistry()
	if err := RegisterAll(registry); err != nil {
		b.Fatal(err)
	}
	engine := investigation.NewEngine(registry)
	input := syntheticFindings(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Correlate(context.Background(), input)
	}
}
