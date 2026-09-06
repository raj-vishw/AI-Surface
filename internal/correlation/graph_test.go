package correlation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func ref(t NodeType) NodeRef { return NodeRef{Type: t, ReferenceID: uuid.New()} }

func TestBuildGraph_DedupesNodesAndDropsDanglingEdges(t *testing.T) {
	a, b := ref(NodeFinding), ref(NodeAsset)
	now := time.Now()
	obs := []Observation{
		{Type: a.Type, ReferenceID: a.ReferenceID, Timestamp: now},
		{Type: b.Type, ReferenceID: b.ReferenceID, Timestamp: now},
	}
	edges := []Edge{
		{Source: a, Target: b, Relationship: RelationshipObservedOn, Provenance: ProvenanceObserved, Confidence: ConfidenceHigh, Evidence: "e", StrategyID: "asset", StrategyVersion: 1},
		{Source: a, Target: b, Relationship: RelationshipObservedOn, Provenance: ProvenanceObserved, Confidence: ConfidenceHigh, Evidence: "e", StrategyID: "asset", StrategyVersion: 1},
	}
	g := BuildGraph(obs, edges, Config{})
	if len(g.Nodes) != 2 {
		t.Fatalf("expected 2 deduped nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 2 {
		t.Fatalf("expected both edges kept (both endpoints exist), got %d", len(g.Edges))
	}

	// An edge referencing an observation never passed in must be dropped.
	dangling := []Edge{{Source: a, Target: ref(NodeAlert), Relationship: RelationshipObservedOn, Provenance: ProvenanceObserved, Confidence: ConfidenceHigh, Evidence: "e", StrategyID: "asset", StrategyVersion: 1}}
	g2 := BuildGraph(obs, dangling, Config{})
	if len(g2.Edges) != 0 {
		t.Fatalf("expected dangling edge dropped, got %d edges", len(g2.Edges))
	}
}

func TestBuildGraph_RespectsMaxNodes(t *testing.T) {
	var obs []Observation
	var edges []Edge
	prev := ref(NodeFinding)
	obs = append(obs, Observation{Type: prev.Type, ReferenceID: prev.ReferenceID, Timestamp: time.Now()})
	for i := 0; i < 5; i++ {
		next := ref(NodeFinding)
		obs = append(obs, Observation{Type: next.Type, ReferenceID: next.ReferenceID, Timestamp: time.Now()})
		edges = append(edges, Edge{Source: prev, Target: next, Relationship: RelationshipFollowedBy, Provenance: ProvenanceInferred, Confidence: ConfidenceLow, Evidence: "e", StrategyID: "temporal", StrategyVersion: 1})
		prev = next
	}
	g := BuildGraph(obs, edges, Config{MaxNodes: 3})
	if !g.NodeLimited {
		t.Fatal("expected NodeLimited to be true")
	}
	if len(g.Nodes) > 3 {
		t.Fatalf("expected at most 3 nodes, got %d", len(g.Nodes))
	}
}

func TestConnectedComponents_SplitsUnrelatedGroups(t *testing.T) {
	a1, a2 := ref(NodeFinding), ref(NodeAsset)
	b1, b2 := ref(NodeFinding), ref(NodeAsset)
	isolated := ref(NodeEndpoint)
	now := time.Now()
	obs := []Observation{
		{Type: a1.Type, ReferenceID: a1.ReferenceID, Timestamp: now}, {Type: a2.Type, ReferenceID: a2.ReferenceID, Timestamp: now},
		{Type: b1.Type, ReferenceID: b1.ReferenceID, Timestamp: now}, {Type: b2.Type, ReferenceID: b2.ReferenceID, Timestamp: now},
		{Type: isolated.Type, ReferenceID: isolated.ReferenceID, Timestamp: now},
	}
	edges := []Edge{
		{Source: a1, Target: a2, Relationship: RelationshipObservedOn, Provenance: ProvenanceObserved, Confidence: ConfidenceHigh, Evidence: "e", StrategyID: "asset", StrategyVersion: 1},
		{Source: b1, Target: b2, Relationship: RelationshipObservedOn, Provenance: ProvenanceObserved, Confidence: ConfidenceHigh, Evidence: "e", StrategyID: "asset", StrategyVersion: 1},
	}
	g := BuildGraph(obs, edges, Config{})
	// An observation with no edge to anything else is never materialized
	// as a node at all (BuildGraph only ever adds a node an edge actually
	// references) — nothing to correlate it with, so it does not become
	// its own trivial one-node "correlation".
	components := ConnectedComponents(g)
	if len(components) != 2 {
		t.Fatalf("expected 2 components (the two unrelated pairs), got %d", len(components))
	}
	total := 0
	for _, c := range components {
		total += len(c.Nodes)
	}
	if total != 4 {
		t.Fatalf("expected only the 4 edge-connected nodes, got %d", total)
	}
	_ = isolated
}

func TestLimitDepth_PrunesBeyondBound(t *testing.T) {
	chain := make([]NodeRef, 6)
	var obs []Observation
	for i := range chain {
		chain[i] = ref(NodeFinding)
		obs = append(obs, Observation{Type: chain[i].Type, ReferenceID: chain[i].ReferenceID, Timestamp: time.Now()})
	}
	var edges []Edge
	for i := 0; i < len(chain)-1; i++ {
		edges = append(edges, Edge{Source: chain[i], Target: chain[i+1], Relationship: RelationshipFollowedBy, Provenance: ProvenanceInferred, Confidence: ConfidenceLow, Evidence: "e", StrategyID: "temporal", StrategyVersion: 1})
	}
	g := BuildGraph(obs, edges, Config{})
	pruned, limited := LimitDepth(g, chain[0], 2)
	if !limited {
		t.Fatal("expected pruning to occur")
	}
	if len(pruned.Nodes) != 3 { // depth 0, 1, 2 from chain[0]
		t.Fatalf("expected 3 nodes within depth 2, got %d", len(pruned.Nodes))
	}
}
