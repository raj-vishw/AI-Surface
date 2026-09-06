package correlation

import (
	"testing"
	"time"
)

func nodeWith(t NodeType, attrs map[string]any) Node {
	return Node{Ref: ref(t), Timestamp: time.Now(), Attributes: attrs}
}

func TestScore_SingleNodeScoresLow(t *testing.T) {
	g := Graph{Nodes: []Node{nodeWith(NodeFinding, nil)}}
	if s := Score(g); s > 20 {
		t.Fatalf("expected a lone, unconnected node to score low, got %d", s)
	}
}

func TestScore_MonotonicWithEdgeConfidenceAndDiversity(t *testing.T) {
	n1, n2 := nodeWith(NodeFinding, nil), nodeWith(NodeAsset, nil)
	weak := Graph{Nodes: []Node{n1, n2}, Edges: []Edge{{Source: n1.Ref, Target: n2.Ref, Confidence: ConfidenceLow}}}
	strong := Graph{Nodes: []Node{n1, n2}, Edges: []Edge{{Source: n1.Ref, Target: n2.Ref, Confidence: ConfidenceHigh}}}
	if Score(strong) <= Score(weak) {
		t.Fatalf("expected a high-confidence edge to score higher than a low-confidence one: strong=%d weak=%d", Score(strong), Score(weak))
	}
}

func TestScore_ClampedTo100(t *testing.T) {
	n1, n2 := nodeWith(NodeFinding, map[string]any{"severity": "critical", "verdict": "malicious"}), nodeWith(NodeIntelligenceRecord, map[string]any{"verdict": "malicious"})
	n3, n4 := nodeWith(NodeDetectionMatch, nil), nodeWith(NodeAsset, nil)
	g := Graph{
		Nodes: []Node{n1, n2, n3, n4},
		Edges: []Edge{
			{Source: n1.Ref, Target: n2.Ref, Confidence: ConfidenceHigh}, {Source: n2.Ref, Target: n3.Ref, Confidence: ConfidenceHigh},
			{Source: n3.Ref, Target: n4.Ref, Confidence: ConfidenceHigh}, {Source: n1.Ref, Target: n4.Ref, Confidence: ConfidenceHigh},
		},
	}
	if s := Score(g); s < 0 || s > 100 {
		t.Fatalf("expected score clamped to [0,100], got %d", s)
	}
}

func TestDeriveSeverity_CappedByLowConfidence(t *testing.T) {
	g := Graph{Nodes: []Node{nodeWith(NodeFinding, map[string]any{"severity": "critical"})}}
	if got := DeriveSeverity(g, ConfidenceHigh); got != "critical" {
		t.Errorf("expected high confidence to preserve max severity, got %s", got)
	}
	if got := DeriveSeverity(g, ConfidenceLow); got != "high" {
		t.Errorf("expected low confidence to cap severity one rank down, got %s", got)
	}
}

func TestDeriveSeverity_NoSeverityDataDefaultsInformational(t *testing.T) {
	g := Graph{Nodes: []Node{nodeWith(NodeAsset, nil)}}
	if got := DeriveSeverity(g, ConfidenceHigh); got != "informational" {
		t.Errorf("expected informational default, got %s", got)
	}
}

func TestConfidenceForScore(t *testing.T) {
	cases := map[int]Confidence{0: ConfidenceLow, 44: ConfidenceLow, 45: ConfidenceMedium, 74: ConfidenceMedium, 75: ConfidenceHigh}
	for score, want := range cases {
		if got := ConfidenceForScore(score); got != want {
			t.Errorf("ConfidenceForScore(%d) = %s, want %s", score, got, want)
		}
	}
}
