package strategies

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/correlation"
)

func TestTemporal_LinksWithinWindow_NotOutside(t *testing.T) {
	base := time.Now()
	a := correlation.Observation{Type: correlation.NodeFinding, ReferenceID: uuid.New(), Timestamp: base}
	inside := correlation.Observation{Type: correlation.NodeAsset, ReferenceID: uuid.New(), Timestamp: base.Add(3 * time.Minute)}
	outside := correlation.Observation{Type: correlation.NodeAsset, ReferenceID: uuid.New(), Timestamp: base.Add(time.Hour)}

	edges, err := NewTemporal().Evaluate(context.Background(), correlation.Input{
		Observations: []correlation.Observation{a, inside, outside}, Config: correlation.Config{TemporalWindow: 5 * time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected exactly 1 edge (a-inside), got %d", len(edges))
	}
}

func TestTemporal_BoundaryIsInclusive(t *testing.T) {
	base := time.Now()
	a := correlation.Observation{Type: correlation.NodeFinding, ReferenceID: uuid.New(), Timestamp: base}
	boundary := correlation.Observation{Type: correlation.NodeAsset, ReferenceID: uuid.New(), Timestamp: base.Add(5 * time.Minute)}
	edges, _ := NewTemporal().Evaluate(context.Background(), correlation.Input{
		Observations: []correlation.Observation{a, boundary}, Config: correlation.Config{TemporalWindow: 5 * time.Minute},
	})
	if len(edges) != 1 {
		t.Fatalf("expected exact-boundary timestamps to still correlate, got %d edges", len(edges))
	}
}

func TestIdentity_RequiresSameAsset(t *testing.T) {
	asset := uuid.New()
	a := correlation.Observation{Type: correlation.NodeFinding, ReferenceID: uuid.New(), AssetID: asset, Category: "authentication", Timestamp: time.Now()}
	sameAsset := correlation.Observation{Type: correlation.NodeDetectionMatch, ReferenceID: uuid.New(), AssetID: asset, Category: "authentication", Timestamp: time.Now()}
	otherAsset := correlation.Observation{Type: correlation.NodeFinding, ReferenceID: uuid.New(), AssetID: uuid.New(), Category: "authentication", Timestamp: time.Now()}

	edges, _ := NewIdentity().Evaluate(context.Background(), correlation.Input{Observations: []correlation.Observation{a, sameAsset, otherAsset}})
	if len(edges) != 1 {
		t.Fatalf("expected exactly 1 edge (a-sameAsset), got %d", len(edges))
	}
}

func TestNetwork_SkipsSameAsset(t *testing.T) {
	sharedIP := "203.0.113.5"
	sameAsset := uuid.New()
	a := correlation.Observation{Type: correlation.NodeFinding, ReferenceID: uuid.New(), AssetID: sameAsset, IP: sharedIP, Timestamp: time.Now()}
	b := correlation.Observation{Type: correlation.NodeAsset, ReferenceID: uuid.New(), AssetID: sameAsset, IP: sharedIP, Timestamp: time.Now()}
	c := correlation.Observation{Type: correlation.NodeFinding, ReferenceID: uuid.New(), AssetID: uuid.New(), IP: sharedIP, Timestamp: time.Now()}

	edges, _ := NewNetwork().Evaluate(context.Background(), correlation.Input{Observations: []correlation.Observation{a, b, c}})
	if len(edges) != 2 { // a-c and b-c both cross an asset boundary; a-b is skipped (same asset)
		t.Fatalf("expected 2 cross-asset shared-IP edges (a-c, b-c), got %d", len(edges))
	}
	for _, e := range edges {
		if e.Confidence != correlation.ConfidenceLow {
			t.Errorf("expected shared-IP edges to be low confidence, got %s", e.Confidence)
		}
	}
}

func TestAsset_ObservedHighConfidence(t *testing.T) {
	asset := uuid.New()
	a := correlation.Observation{Type: correlation.NodeFinding, ReferenceID: uuid.New(), AssetID: asset, Timestamp: time.Now()}
	b := correlation.Observation{Type: correlation.NodeDetectionMatch, ReferenceID: uuid.New(), AssetID: asset, Timestamp: time.Now()}
	edges, _ := NewAsset().Evaluate(context.Background(), correlation.Input{Observations: []correlation.Observation{a, b}})
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Provenance != correlation.ProvenanceObserved || edges[0].Confidence != correlation.ConfidenceHigh {
		t.Errorf("expected an observed, high-confidence edge, got %+v", edges[0])
	}
}

func TestDetection_SkipsSameRule(t *testing.T) {
	asset := uuid.New()
	rule1, rule2 := uuid.New(), uuid.New()
	a := correlation.Observation{Type: correlation.NodeDetectionMatch, ReferenceID: uuid.New(), AssetID: asset, RuleID: rule1, Timestamp: time.Now()}
	b := correlation.Observation{Type: correlation.NodeDetectionMatch, ReferenceID: uuid.New(), AssetID: asset, RuleID: rule1, Timestamp: time.Now().Add(time.Minute)}
	c := correlation.Observation{Type: correlation.NodeDetectionMatch, ReferenceID: uuid.New(), AssetID: asset, RuleID: rule2, Timestamp: time.Now().Add(2 * time.Minute)}

	edges, _ := NewDetection().Evaluate(context.Background(), correlation.Input{Observations: []correlation.Observation{a, b, c}})
	if len(edges) != 2 { // a-c and b-c, never a-b (same rule)
		t.Fatalf("expected 2 cross-rule edges, got %d", len(edges))
	}
}

func TestIntelligence_LabelsAsExternal(t *testing.T) {
	asset := correlation.Observation{Type: correlation.NodeAsset, ReferenceID: uuid.New(), IP: "198.51.100.9", Timestamp: time.Now()}
	record := correlation.Observation{
		Type: correlation.NodeIntelligenceRecord, ReferenceID: uuid.New(), Timestamp: time.Now(),
		IndicatorValue: "198.51.100.9", Verdict: "malicious", Confidence: "high",
	}
	edges, _ := NewIntelligence().Evaluate(context.Background(), correlation.Input{Observations: []correlation.Observation{asset, record}})
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Relationship != correlation.RelationshipEnrichedBy {
		t.Errorf("expected enriched_by relationship, got %s", edges[0].Relationship)
	}
	if got := edges[0].Evidence; !contains(got, "EXTERNAL") {
		t.Errorf("expected evidence to explicitly label the record as external, got %q", got)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRegisterAll_RegistersEveryStrategyOnce(t *testing.T) {
	reg := correlation.NewStrategyRegistry()
	if err := RegisterAll(reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.All()) != 6 {
		t.Fatalf("expected 6 registered strategies, got %d", len(reg.All()))
	}
	if err := RegisterAll(correlation.NewStrategyRegistry()); err != nil {
		t.Fatalf("expected a fresh registry to accept every strategy without collision, got %v", err)
	}
}
