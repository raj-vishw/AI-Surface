package correlation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

func TestTechnologyRule_LinksSameAssetTechnology(t *testing.T) {
	assetID := uuid.New()
	f := newFinding(assetID, "information_disclosure", time.Now())
	tech := investigation.TechnologyObservation{ID: uuid.New(), AssetID: assetID, Technology: "nginx", Version: "1.18.0"}

	input := investigation.Input{Findings: []investigation.FindingObservation{f}, Technologies: []investigation.TechnologyObservation{tech}}
	rels, err := technologyRule{}.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rels) != 1 || rels[0].TargetType != investigation.EntityTechnology || rels[0].TargetID != tech.ID {
		t.Fatalf("unexpected relationships: %#v", rels)
	}
}

func TestTechnologyRule_NeverClaimsExploitation(t *testing.T) {
	assetID := uuid.New()
	f := newFinding(assetID, "information_disclosure", time.Now())
	tech := investigation.TechnologyObservation{ID: uuid.New(), AssetID: assetID, Technology: "nginx"}

	rels, _ := technologyRule{}.Evaluate(context.Background(), investigation.Input{
		Findings: []investigation.FindingObservation{f}, Technologies: []investigation.TechnologyObservation{tech},
	})
	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
	if !strings.Contains(rels[0].Explanation, "not a claim") {
		t.Fatalf("expected explanation to explicitly disclaim exploitability, got %q", rels[0].Explanation)
	}
}

func TestTechnologyRule_DifferentAssetIgnored(t *testing.T) {
	f := newFinding(uuid.New(), "x", time.Now())
	tech := investigation.TechnologyObservation{ID: uuid.New(), AssetID: uuid.New(), Technology: "nginx"}
	rels, _ := technologyRule{}.Evaluate(context.Background(), investigation.Input{
		Findings: []investigation.FindingObservation{f}, Technologies: []investigation.TechnologyObservation{tech},
	})
	if len(rels) != 0 {
		t.Fatalf("expected no relationship across different assets, got %d", len(rels))
	}
}
