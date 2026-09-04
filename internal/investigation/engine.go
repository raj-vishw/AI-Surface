package investigation

import (
	"context"
	"fmt"
)

// RuleError is one rule's failure during a Result — a rule failing must
// never abort the rest of the correlation run (phase9.md §78).
type RuleError struct {
	RuleID string
	Err    error
}

func (e RuleError) Error() string {
	return fmt.Sprintf("rule %s: %v", e.RuleID, e.Err)
}

// Result is one Engine.Correlate call's outcome.
type Result struct {
	Relationships []Relationship
	Errors        []RuleError
}

// Engine runs a Registry's active rules against one Input and merges
// their output. It performs no persistence of its own — see
// internal/service/investigation for that.
type Engine struct {
	registry *Registry
}

// NewEngine builds an Engine backed by registry.
func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// Correlate runs every active, config-enabled rule against input,
// isolating each rule's failure (phase9.md §78), and merging same-key
// results via MergeRelationships before returning.
func (e *Engine) Correlate(ctx context.Context, input Input) Result {
	var result Result

	for _, rule := range e.registry.Active() {
		if !input.Config.RuleEnabled(rule.ID()) {
			continue
		}
		if err := ctx.Err(); err != nil {
			result.Errors = append(result.Errors, RuleError{RuleID: rule.ID(), Err: err})
			break
		}

		relationships, err := rule.Evaluate(ctx, input)
		if err != nil {
			result.Errors = append(result.Errors, RuleError{RuleID: rule.ID(), Err: err})
			continue
		}
		for i := range relationships {
			if relationships[i].RuleID == "" {
				relationships[i].RuleID = rule.ID()
			}
			if relationships[i].RuleVersion == 0 {
				relationships[i].RuleVersion = rule.Version()
			}
		}
		result.Relationships = append(result.Relationships, relationships...)
	}

	result.Relationships = MergeRelationships(result.Relationships)
	return result
}
