package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func TestAuthenticationColocationRule_SameAssetSameCategory(t *testing.T) {
	assetID := uuid.New()
	f1 := newFinding(assetID, "authentication", time.Now())
	f2 := newFinding(assetID, "authentication", time.Now())
	rels, err := authenticationColocationRule{}.Evaluate(context.Background(), investigation.Input{Findings: []investigation.FindingObservation{f1, f2}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
}

func TestAuthenticationColocationRule_IgnoresOtherCategories(t *testing.T) {
	assetID := uuid.New()
	f1 := newFinding(assetID, "authentication", time.Now())
	f2 := newFinding(assetID, "security_headers", time.Now())
	rels, _ := authenticationColocationRule{}.Evaluate(context.Background(), investigation.Input{Findings: []investigation.FindingObservation{f1, f2}})
	if len(rels) != 0 {
		t.Fatalf("expected no relationship for mixed categories, got %d", len(rels))
	}
}
