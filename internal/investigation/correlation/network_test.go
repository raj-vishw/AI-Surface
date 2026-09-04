package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func TestSameServiceRule_SharedIPLinked(t *testing.T) {
	asset1ID, asset2ID := uuid.New(), uuid.New()
	f1 := newFinding(asset1ID, "x", time.Now())
	f2 := newFinding(asset2ID, "y", time.Now())

	input := investigation.Input{
		Findings: []investigation.FindingObservation{f1, f2},
		Assets: map[uuid.UUID]investigation.AssetObservation{
			asset1ID: {ID: asset1ID, IP: "203.0.113.1"},
			asset2ID: {ID: asset2ID, IP: "203.0.113.1"},
		},
	}
	rels, err := sameServiceRule{}.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
}

func TestSameServiceRule_AloneNeverCrossesDefaultThreshold(t *testing.T) {
	// phase9.md §39/§67: "same IP = same incident" must be a weak signal
	// — never sufficient on its own to confirm a relationship.
	if sameNetworkScore >= investigation.DefaultThreshold {
		t.Fatalf("same-network score (%d) must stay below the default threshold (%d) on its own", sameNetworkScore, investigation.DefaultThreshold)
	}
}

func TestSameServiceRule_DifferentIPNoRelationship(t *testing.T) {
	asset1ID, asset2ID := uuid.New(), uuid.New()
	f1 := newFinding(asset1ID, "x", time.Now())
	f2 := newFinding(asset2ID, "y", time.Now())
	input := investigation.Input{
		Findings: []investigation.FindingObservation{f1, f2},
		Assets: map[uuid.UUID]investigation.AssetObservation{
			asset1ID: {ID: asset1ID, IP: "203.0.113.1"},
			asset2ID: {ID: asset2ID, IP: "203.0.113.2"},
		},
	}
	rels, _ := sameServiceRule{}.Evaluate(context.Background(), input)
	if len(rels) != 0 {
		t.Fatalf("expected no relationship for different IPs, got %d", len(rels))
	}
}

func TestSameServiceRule_SkipsSameAsset(t *testing.T) {
	assetID := uuid.New()
	f1 := newFinding(assetID, "x", time.Now())
	f2 := newFinding(assetID, "y", time.Now())
	input := investigation.Input{
		Findings: []investigation.FindingObservation{f1, f2},
		Assets:   map[uuid.UUID]investigation.AssetObservation{assetID: {ID: assetID, IP: "203.0.113.1"}},
	}
	rels, _ := sameServiceRule{}.Evaluate(context.Background(), input)
	if len(rels) != 0 {
		t.Fatalf("expected same_asset_findings (not this rule) to cover same-asset pairs, got %d", len(rels))
	}
}
