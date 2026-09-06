package correlation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestComputeFingerprint_DeterministicAndOrderIndependent(t *testing.T) {
	target := uuid.New()
	n1, n2 := nodeWith(NodeFinding, nil), nodeWith(NodeAsset, nil)
	g1 := Graph{Nodes: []Node{n1, n2}}
	g2 := Graph{Nodes: []Node{n2, n1}} // reversed order
	window := time.Now().Truncate(time.Hour)

	fp1 := ComputeFingerprint(target, g1, window, time.Hour)
	fp2 := ComputeFingerprint(target, g2, window, time.Hour)
	if fp1 != fp2 {
		t.Fatal("expected fingerprint to be independent of node ordering")
	}
}

func TestComputeFingerprint_DistinguishesDifferentGroups(t *testing.T) {
	target := uuid.New()
	window := time.Now().Truncate(time.Hour)
	g1 := Graph{Nodes: []Node{nodeWith(NodeFinding, nil)}}
	g2 := Graph{Nodes: []Node{nodeWith(NodeFinding, nil)}}
	if ComputeFingerprint(target, g1, window, time.Hour) == ComputeFingerprint(target, g2, window, time.Hour) {
		t.Fatal("expected distinct node sets to produce distinct fingerprints")
	}
}

func TestComputeFingerprint_SameWindowBucketCollapses(t *testing.T) {
	target := uuid.New()
	n := nodeWith(NodeFinding, nil)
	g := Graph{Nodes: []Node{n}}
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	fp1 := ComputeFingerprint(target, g, base, time.Hour)
	fp2 := ComputeFingerprint(target, g, base.Add(10*time.Minute), time.Hour)
	if fp1 != fp2 {
		t.Fatal("expected timestamps within the same hourly bucket to collapse to one fingerprint")
	}
}
