package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func newFinding(assetID uuid.UUID, category string, firstSeen time.Time) investigation.FindingObservation {
	return investigation.FindingObservation{ID: uuid.New(), AssetID: assetID, Category: category, FirstSeen: firstSeen}
}

func TestSameAssetRule_LinksSharedAsset(t *testing.T) {
	assetID := uuid.New()
	f1 := newFinding(assetID, "security_headers", time.Now())
	f2 := newFinding(assetID, "certificate", time.Now())

	rels, err := sameAssetRule{}.Evaluate(context.Background(), investigation.Input{Findings: []investigation.FindingObservation{f1, f2}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 || rels[0].Score != sameAssetScore {
		t.Fatalf("expected 1 relationship scored %d, got %#v", sameAssetScore, rels)
	}
	if rels[0].Explanation == "" {
		t.Fatal("expected a non-empty explanation")
	}
}

func TestSameAssetRule_DifferentAssetsNoRelationship(t *testing.T) {
	f1 := newFinding(uuid.New(), "x", time.Now())
	f2 := newFinding(uuid.New(), "x", time.Now())

	rels, _ := sameAssetRule{}.Evaluate(context.Background(), investigation.Input{Findings: []investigation.FindingObservation{f1, f2}})
	if len(rels) != 0 {
		t.Fatalf("expected no relationship for different assets, got %d", len(rels))
	}
}

func TestSameAssetRule_ThreeFindingsProducesThreePairs(t *testing.T) {
	assetID := uuid.New()
	fs := []investigation.FindingObservation{
		newFinding(assetID, "a", time.Now()), newFinding(assetID, "b", time.Now()), newFinding(assetID, "c", time.Now()),
	}
	rels, _ := sameAssetRule{}.Evaluate(context.Background(), investigation.Input{Findings: fs})
	if len(rels) != 3 {
		t.Fatalf("expected 3 pairwise relationships for 3 findings, got %d", len(rels))
	}
}
