package correlation

import (
	"context"
	"errors"
	"testing"
)

type stubStrategy struct {
	id    string
	edges []Edge
	err   error
	calls *int
}

func (s stubStrategy) ID() string          { return s.id }
func (s stubStrategy) Name() string        { return s.id }
func (s stubStrategy) Description() string { return s.id }
func (s stubStrategy) Version() int        { return 1 }
func (s stubStrategy) Evaluate(_ context.Context, _ Input) ([]Edge, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.edges, s.err
}

func TestEngine_Correlate_IsolatesStrategyFailures(t *testing.T) {
	reg := NewStrategyRegistry()
	okCalls := 0
	_ = reg.Register(stubStrategy{id: "ok", edges: []Edge{{Source: ref(NodeFinding), Target: ref(NodeAsset), Relationship: RelationshipRelatedTo, Provenance: ProvenanceInferred, Confidence: ConfidenceLow, Evidence: "e"}}, calls: &okCalls})
	_ = reg.Register(stubStrategy{id: "broken", err: errors.New("boom")})

	engine := NewEngine(reg)
	result := engine.Correlate(context.Background(), Input{})

	if len(result.Errors) != 1 || result.Errors[0].StrategyID != "broken" {
		t.Fatalf("expected exactly one isolated error from 'broken', got %+v", result.Errors)
	}
	if len(result.Edges) != 1 {
		t.Fatalf("expected the 'ok' strategy's edge to still be produced, got %d", len(result.Edges))
	}
	if okCalls != 1 {
		t.Fatalf("expected 'ok' strategy to run exactly once, got %d", okCalls)
	}
}

func TestEngine_Correlate_DisabledStrategyDoesNotRun(t *testing.T) {
	reg := NewStrategyRegistry()
	calls := 0
	_ = reg.Register(stubStrategy{id: "s1", calls: &calls})

	engine := NewEngine(reg)
	engine.Correlate(context.Background(), Input{Config: Config{Strategies: map[string]bool{"s1": false}}})
	if calls != 0 {
		t.Fatalf("expected disabled strategy to never run, got %d calls", calls)
	}
}

func TestEngine_Correlate_Deterministic(t *testing.T) {
	reg := NewStrategyRegistry()
	edge := Edge{Source: ref(NodeFinding), Target: ref(NodeAsset), Relationship: RelationshipRelatedTo, Provenance: ProvenanceInferred, Confidence: ConfidenceLow, Evidence: "e"}
	_ = reg.Register(stubStrategy{id: "s1", edges: []Edge{edge, edge}}) // same strategy firing "twice" for the same pair

	engine := NewEngine(reg)
	result := engine.Correlate(context.Background(), Input{})
	if len(result.Edges) != 1 {
		t.Fatalf("expected duplicate same-key edges collapsed to 1, got %d", len(result.Edges))
	}
}

func TestEngine_Correlate_TruncatesCandidatesBeyondMax(t *testing.T) {
	reg := NewStrategyRegistry()
	var seenCount int
	_ = reg.Register(stubStrategy{id: "s1", edges: nil, calls: nil})
	_ = seenCount

	engine := NewEngine(reg)
	obs := make([]Observation, 10)
	result := engine.Correlate(context.Background(), Input{Observations: obs, Config: Config{MaxCandidates: 3}})
	if !result.Truncated {
		t.Fatal("expected Truncated to be true when observations exceed MaxCandidates")
	}
}
