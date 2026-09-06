package ai

import (
	"testing"
	"time"
)

func TestEvidenceGaps_FlagsMissingCategories(t *testing.T) {
	ctx := Context{Facts: []Fact{{Type: FactAlert, ID: "a1", Timestamp: time.Now(), Summary: "x"}}}
	gaps := evidenceGaps(ctx)
	if len(gaps) == 0 {
		t.Fatal("expected at least one evidence gap for a context with only an alert")
	}
	found := false
	for _, g := range gaps {
		if containsSubstring(g, "asset context") {
			found = true
		}
	}
	if !found {
		t.Errorf("gaps = %v, want one mentioning missing asset context", gaps)
	}
}

func TestEvidenceGaps_NeverFabricatesSpecifics(t *testing.T) {
	ctx := Context{}
	for _, g := range evidenceGaps(ctx) {
		if containsSubstring(g, "[") {
			t.Errorf("evidence gap %q references a citation that cannot exist for missing evidence", g)
		}
	}
}

func TestGenerateInvestigationQuestions_TiedToActualGaps(t *testing.T) {
	ctx := Context{Facts: []Fact{{Type: FactAlert, ID: "a1", Timestamp: time.Now(), Summary: "x"}}}
	qs := GenerateInvestigationQuestions(ctx)
	if len(qs) == 0 {
		t.Fatal("expected at least one question")
	}
	found := false
	for _, q := range qs {
		if containsSubstring(q, "asset") {
			found = true
		}
	}
	if !found {
		t.Errorf("questions = %v, want one about the missing asset", qs)
	}
}

func TestSummarizeInvestigation_NeverOmitsUnknownSection(t *testing.T) {
	ctx := sampleContext()
	r := SummarizeInvestigation(ctx)
	if len(r.Unknown) == 0 {
		t.Error("Unknown section must never be empty (phase13.md §16)")
	}
}

func TestSummarizeInvestigation_EveryObservedLineHasCitation(t *testing.T) {
	ctx := sampleContext()
	r := SummarizeInvestigation(ctx)
	for _, line := range r.Observed {
		if len(ExtractCitations(line)) == 0 {
			t.Errorf("observed line has no citation: %q", line)
		}
	}
}

func TestAnalyzeAttackChain_NoStagesReportsGapNotFabrication(t *testing.T) {
	ctx := Context{Facts: []Fact{{Type: FactCorrelation, ID: "c1", Timestamp: time.Now(), Summary: "x"}}}
	r := AnalyzeAttackChain(ctx)
	if len(r.Observed) != 0 || len(r.Inferred) != 0 {
		t.Error("no stages present should produce no fabricated stage narrative")
	}
	if r.Summary == "" {
		t.Error("expected a summary explaining no chain exists")
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
