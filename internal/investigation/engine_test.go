package investigation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestEngine_Correlate_RunsRules(t *testing.T) {
	r := NewRegistry()
	src, tgt := uuid.New(), uuid.New()
	_ = r.Register(stubRule{id: "a", relationships: []Relationship{
		{SourceType: EntityFinding, SourceID: src, TargetType: EntityFinding, TargetID: tgt, Type: RelationshipSameAsset, Score: 30, Explanation: "x"},
	}})

	engine := NewEngine(r)
	result := engine.Correlate(context.Background(), Input{})

	if len(result.Relationships) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(result.Relationships))
	}
	if result.Relationships[0].RuleID != "a" {
		t.Errorf("expected RuleID filled in, got %q", result.Relationships[0].RuleID)
	}
	if result.Relationships[0].RuleVersion != 1 {
		t.Errorf("expected RuleVersion filled in, got %d", result.Relationships[0].RuleVersion)
	}
}

func TestEngine_Correlate_IsolatesRuleFailure(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "broken", err: errors.New("boom")})
	_ = r.Register(stubRule{id: "healthy", relationships: []Relationship{{RuleID: "healthy", Explanation: "x"}}})

	engine := NewEngine(r)
	result := engine.Correlate(context.Background(), Input{})

	if len(result.Relationships) != 1 {
		t.Fatalf("expected the healthy rule's relationship to survive, got %d", len(result.Relationships))
	}
	if len(result.Errors) != 1 || result.Errors[0].RuleID != "broken" {
		t.Fatalf("expected exactly one structured error for 'broken', got %#v", result.Errors)
	}
}

func TestEngine_Correlate_RespectsRuleEnabledConfig(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "a", relationships: []Relationship{{Explanation: "x"}}})

	engine := NewEngine(r)
	result := engine.Correlate(context.Background(), Input{Config: Config{Rules: map[string]bool{"a": false}}})

	if len(result.Relationships) != 0 {
		t.Fatalf("expected 0 relationships with rule disabled, got %d", len(result.Relationships))
	}
}

func TestEngine_Correlate_ContextCancelled(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(stubRule{id: "a", relationships: []Relationship{{Explanation: "x"}}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	engine := NewEngine(r)
	result := engine.Correlate(ctx, Input{})

	if len(result.Relationships) != 0 {
		t.Fatalf("expected no relationships once context is cancelled, got %d", len(result.Relationships))
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected a structured error for the cancelled context, got %#v", result.Errors)
	}
}

func TestConfidenceForScore(t *testing.T) {
	cases := []struct {
		score int
		want  Confidence
	}{
		{10, ConfidenceVeryLow}, {30, ConfidenceLow}, {55, ConfidenceMedium},
		{75, ConfidenceHigh}, {95, ConfidenceVeryHigh},
	}
	for _, tc := range cases {
		if got := ConfidenceForScore(tc.score); got != tc.want {
			t.Errorf("ConfidenceForScore(%d) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestConfig_Effective(t *testing.T) {
	cfg := Config{}
	if cfg.EffectiveThreshold() != DefaultThreshold {
		t.Errorf("expected default threshold, got %d", cfg.EffectiveThreshold())
	}
	if cfg.EffectiveTemporalWindow() != DefaultTemporalWindow {
		t.Errorf("expected default temporal window, got %v", cfg.EffectiveTemporalWindow())
	}
	if !cfg.RuleEnabled("anything") {
		t.Error("expected nil Rules map to mean everything enabled")
	}
}

func TestMergeRelationships_DedupsSameKey(t *testing.T) {
	id1, id2 := uuid.New(), uuid.New()
	rels := []Relationship{
		{SourceType: EntityFinding, SourceID: id1, TargetType: EntityFinding, TargetID: id2, Type: RelationshipSameAsset, RuleID: "r"},
		{SourceType: EntityFinding, SourceID: id1, TargetType: EntityFinding, TargetID: id2, Type: RelationshipSameAsset, RuleID: "r"},
	}
	merged := MergeRelationships(rels)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged relationship, got %d", len(merged))
	}
}
