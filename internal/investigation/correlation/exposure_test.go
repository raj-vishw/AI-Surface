package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func TestNewAssetWithFindingRule_WithinWindow(t *testing.T) {
	now := time.Now()
	assetID := uuid.New()
	f := newFinding(assetID, "exposure", now)

	input := investigation.Input{
		Findings: []investigation.FindingObservation{f},
		Assets:   map[uuid.UUID]investigation.AssetObservation{assetID: {ID: assetID, Hostname: "admin.example.test", FirstSeen: now.Add(-1 * time.Minute)}},
		Config:   investigation.Config{TemporalWindow: 5 * time.Minute},
	}
	rels, err := newAssetWithFindingRule{}.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
}

func TestNewAssetWithFindingRule_OldAssetIgnored(t *testing.T) {
	now := time.Now()
	assetID := uuid.New()
	f := newFinding(assetID, "exposure", now)

	input := investigation.Input{
		Findings: []investigation.FindingObservation{f},
		Assets:   map[uuid.UUID]investigation.AssetObservation{assetID: {ID: assetID, FirstSeen: now.Add(-24 * time.Hour)}},
		Config:   investigation.Config{TemporalWindow: 5 * time.Minute},
	}
	rels, _ := newAssetWithFindingRule{}.Evaluate(context.Background(), input)
	if len(rels) != 0 {
		t.Fatalf("expected no relationship for a long-known asset, got %d", len(rels))
	}
}
