package correlation

import (
	"context"
	"fmt"
)

// StrategyError is one strategy's failure during a Result — a strategy
// failing must never abort the rest of the correlation run (phase12.md
// §69/§93's failure isolation).
type StrategyError struct {
	StrategyID string
	Err        error
}

func (e StrategyError) Error() string { return fmt.Sprintf("strategy %s: %v", e.StrategyID, e.Err) }

// Result is one Engine.Correlate call's outcome.
type Result struct {
	Edges  []Edge
	Errors []StrategyError
	// Truncated reports whether candidate selection dropped observations
	// to stay within Config.EffectiveMaxCandidates (phase12.md §62's
	// "when limits are reached, stop expansion and explain the
	// limitation").
	Truncated bool
}

// Engine runs a StrategyRegistry's active strategies against one Input
// and merges their output (phase12.md §24). It performs no persistence of
// its own — see internal/service/correlation for that.
type Engine struct {
	registry *StrategyRegistry
}

// NewEngine builds an Engine backed by registry.
func NewEngine(registry *StrategyRegistry) *Engine {
	return &Engine{registry: registry}
}

// Correlate runs every active, config-enabled strategy against input,
// isolating each strategy's failure and bounding the candidate set to
// Config.EffectiveMaxCandidates before evaluation (phase12.md §64/§65 —
// candidate selection happens once here rather than inside every
// strategy, so no strategy needs its own truncation logic). Given the
// same Input and strategy versions, Correlate always produces the same
// Result (phase12.md §25).
func (e *Engine) Correlate(ctx context.Context, input Input) Result {
	var result Result

	if maxCandidates := input.Config.EffectiveMaxCandidates(); len(input.Observations) > maxCandidates {
		input.Observations = input.Observations[:maxCandidates]
		result.Truncated = true
	}

	for _, strategy := range e.registry.Active() {
		if !input.Config.StrategyEnabled(strategy.ID()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, StrategyError{StrategyID: strategy.ID(), Err: err})
			break
		}

		edges, err := strategy.Evaluate(ctx, input)
		if err != nil {
			result.Errors = append(result.Errors, StrategyError{StrategyID: strategy.ID(), Err: err})
			continue
		}
		for i := range edges {
			if edges[i].StrategyID == "" {
				edges[i].StrategyID = strategy.ID()
			}
			if edges[i].StrategyVersion == 0 {
				edges[i].StrategyVersion = strategy.Version()
			}
		}
		result.Edges = append(result.Edges, edges...)
	}

	result.Edges = dedupEdges(result.Edges)
	return result
}
