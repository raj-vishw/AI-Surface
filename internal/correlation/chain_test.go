package correlation

import (
	"testing"
	"time"
)

func TestBuildChain_OrdersStagesChronologicallyAndOmitsUnclassified(t *testing.T) {
	asset := Node{Ref: ref(NodeAsset), Timestamp: time.Now().Add(-time.Hour)}
	auth := Node{Ref: ref(NodeFinding), Timestamp: time.Now().Add(-30 * time.Minute), Attributes: map[string]any{"category": "authentication"}}
	unclassified := Node{Ref: ref(NodeFinding), Timestamp: time.Now(), Attributes: map[string]any{"category": "cryptography"}}

	g := Graph{
		Nodes: []Node{asset, auth, unclassified},
		Edges: []Edge{{Source: asset.Ref, Target: auth.Ref, Confidence: ConfidenceMedium}},
	}
	chain := BuildChain(g)

	if len(chain.Stages) != 2 {
		t.Fatalf("expected 2 classified stages (asset->initial_activity, auth->authentication), got %d: %+v", len(chain.Stages), chain.Stages)
	}
	if chain.Stages[0].Stage != StageInitialActivity {
		t.Errorf("expected initial_activity first (earliest timestamp), got %s", chain.Stages[0].Stage)
	}
	if chain.Stages[1].Stage != StageAuthentication {
		t.Errorf("expected authentication second, got %s", chain.Stages[1].Stage)
	}
	for _, s := range chain.Stages {
		if s.Stage == "cryptography" {
			t.Fatal("an unclassified node must never be forced into an invented stage")
		}
	}
}

func TestBuildChain_NoEvidenceMeansNoStages(t *testing.T) {
	g := Graph{Nodes: []Node{{Ref: ref(NodeFinding), Timestamp: time.Now(), Attributes: map[string]any{"category": "cryptography"}}}}
	chain := BuildChain(g)
	if len(chain.Stages) != 0 {
		t.Fatalf("expected no stages for entirely unclassifiable evidence (a gap, not an invented stage), got %d", len(chain.Stages))
	}
}

func TestClassifyByKeyword(t *testing.T) {
	cases := map[string]StageType{
		"privilege_escalation": StagePrivilegeChange,
		"persistence_backdoor": StagePersistenceSignal,
		"discovery_scan":       StageDiscoverySignal,
		"data_exfiltration":    StageDataAccess,
		"impact_destructive":   StageImpactSignal,
		"generic_rule":         StageExecution,
	}
	for input, want := range cases {
		got, ok := classifyByKeyword(input)
		if !ok || got != want {
			t.Errorf("classifyByKeyword(%q) = %s, %v; want %s, true", input, got, ok, want)
		}
	}
	if _, ok := classifyByKeyword(""); ok {
		t.Error("expected empty rule category to classify as nothing")
	}
}

func TestChainConfidence_WeightedNotAveraged(t *testing.T) {
	// One high-confidence stage backed by many pieces of evidence should
	// outweigh one low-confidence stage backed by a single node — a bare
	// average would treat them equally.
	heavy := StageDraft{Stage: StageAuthentication, Confidence: ConfidenceHigh, Evidence: make([]NodeRef, 5)}
	light := StageDraft{Stage: StageDiscoverySignal, Confidence: ConfidenceLow, Evidence: make([]NodeRef, 1)}
	got := chainConfidence([]StageDraft{heavy, light})
	if got != ConfidenceHigh {
		t.Errorf("expected the heavily-evidenced high-confidence stage to dominate, got %s", got)
	}
}
