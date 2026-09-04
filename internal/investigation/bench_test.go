package investigation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// syntheticInput builds a synthetic Input with n findings spread across
// n/5 assets (so same_asset_findings has real pairs to find) — used to
// benchmark correlation at a scale larger than any single hand-written
// test needs, without touching a real database (phase9.md §76: "do not
// use real customer data").
func syntheticInput(n int) Input {
	in := Input{Assets: map[uuid.UUID]AssetObservation{}, Endpoints: map[uuid.UUID]EndpointObservation{}}
	assetIDs := make([]uuid.UUID, 0, n/5+1)
	for i := 0; i < n/5+1; i++ {
		id := uuid.New()
		assetIDs = append(assetIDs, id)
		in.Assets[id] = AssetObservation{ID: id, Hostname: "asset.test", FirstSeen: time.Now()}
	}
	now := time.Now()
	for i := 0; i < n; i++ {
		in.Findings = append(in.Findings, FindingObservation{
			ID: uuid.New(), AssetID: assetIDs[i%len(assetIDs)], Category: "configuration",
			Severity: "medium", FirstSeen: now.Add(time.Duration(i) * time.Second),
		})
	}
	return in
}

func BenchmarkEngine_Correlate_1000Findings(b *testing.B) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "bench", relationships: nil})
	engine := NewEngine(r)
	input := syntheticInput(1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Correlate(context.Background(), input)
	}
}

func BenchmarkMergeRelationships(b *testing.B) {
	rels := make([]Relationship, 0, 2000)
	for i := 0; i < 1000; i++ {
		rels = append(rels, Relationship{SourceID: uuid.New(), TargetID: uuid.New(), Type: RelationshipSameAsset, RuleID: "r"})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MergeRelationships(rels)
	}
}
