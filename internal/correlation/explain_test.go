package correlation

import (
	"strings"
	"testing"
	"time"
)

func TestExplain_NeverAssertsConfirmedAttack(t *testing.T) {
	n1, n2 := nodeWith(NodeFinding, nil), nodeWith(NodeAsset, nil)
	g := Graph{
		Nodes: []Node{n1, n2},
		Edges: []Edge{{Source: n1.Ref, Target: n2.Ref, Relationship: RelationshipObservedOn, Confidence: ConfidenceHigh, Evidence: "shared asset", StrategyID: "asset"}},
	}
	out := Explain(g, 60, ConfidenceMedium, time.Hour)

	lower := strings.ToLower(out)
	if strings.Contains(lower, "is a confirmed attack") || strings.Contains(lower, "attacker compromised") {
		t.Fatalf("Explain must never assert an unsupported conclusion, got: %s", out)
	}
	if !strings.Contains(lower, "not a confirmed attack") {
		t.Error("expected Explain to explicitly disclaim a confirmed-attack conclusion")
	}
	if !strings.Contains(out, "shared asset") {
		t.Error("expected the edge's own evidence text to appear in the explanation")
	}
	if !strings.Contains(out, "Score: 60") || !strings.Contains(out, "Confidence: medium") {
		t.Error("expected score and confidence to be stated explicitly")
	}
}
