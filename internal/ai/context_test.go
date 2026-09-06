package ai

import (
	"testing"
	"time"
)

func sampleFacts() []Fact {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []Fact{
		{Type: FactAlert, ID: "a1", Timestamp: base, Summary: "alert one", Provenance: ProvenanceObserved},
		{Type: FactAlert, ID: "a2", Timestamp: base.Add(time.Minute), Summary: "alert two", Provenance: ProvenanceObserved},
		{Type: FactFinding, ID: "f1", Timestamp: base.Add(2 * time.Minute), Summary: "finding one", Provenance: ProvenanceObserved},
	}
}

func TestContext_HashIsOrderIndependent(t *testing.T) {
	facts := sampleFacts()
	c1 := Context{TargetID: "t1", Facts: facts}
	reversed := []Fact{facts[2], facts[0], facts[1]}
	c2 := Context{TargetID: "t1", Facts: reversed}

	if c1.Hash() != c2.Hash() {
		t.Error("Hash depends on fact assembly order, want order-independent")
	}
}

func TestContext_HashChangesWithContent(t *testing.T) {
	facts := sampleFacts()
	c1 := Context{TargetID: "t1", Facts: facts}
	changed := make([]Fact, len(facts))
	copy(changed, facts)
	changed[0].Summary = "a materially different statement"
	c2 := Context{TargetID: "t1", Facts: changed}

	if c1.Hash() == c2.Hash() {
		t.Error("Hash did not change when fact content changed")
	}
}

func TestContext_CitationSetMatchesFacts(t *testing.T) {
	c := Context{Facts: sampleFacts()}
	set := c.CitationSet()
	if !set["[alert:a1]"] || !set["[finding:f1]"] {
		t.Errorf("CitationSet = %v, missing expected tokens", set)
	}
	if set["[alert:nonexistent]"] {
		t.Error("CitationSet contains an unexpected token")
	}
}

func TestTruncate_CapsPerTypeAndTotal_Deterministically(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var facts []Fact
	for i := 0; i < 10; i++ {
		facts = append(facts, Fact{Type: FactFinding, ID: string(rune('a' + i)), Timestamp: base.Add(time.Duration(i) * time.Minute)})
	}

	kept, truncated := Truncate(facts, Limits{MaxFactsPerType: 3, MaxTotalFacts: 100})
	if !truncated {
		t.Fatal("expected truncated = true")
	}
	if len(kept) != 3 {
		t.Fatalf("len(kept) = %d, want 3", len(kept))
	}
	// Newest-first selection means the last three (indices 7,8,9) survive.
	wantIDs := map[string]bool{"h": true, "i": true, "j": true}
	for _, f := range kept {
		if !wantIDs[f.ID] {
			t.Errorf("unexpected fact kept: %s", f.ID)
		}
	}

	kept2, truncated2 := Truncate(facts, Limits{MaxFactsPerType: 3, MaxTotalFacts: 100})
	if truncated != truncated2 || len(kept) != len(kept2) {
		t.Error("Truncate is not deterministic across identical calls")
	}
	for i := range kept {
		if kept[i].ID != kept2[i].ID {
			t.Error("Truncate produced a different order across identical calls")
		}
	}
}

func TestTruncate_UnderLimitIsUntouched(t *testing.T) {
	facts := sampleFacts()
	kept, truncated := Truncate(facts, Limits{})
	if truncated {
		t.Error("truncated = true for a small fact list under default limits")
	}
	if len(kept) != len(facts) {
		t.Errorf("len(kept) = %d, want %d", len(kept), len(facts))
	}
}
