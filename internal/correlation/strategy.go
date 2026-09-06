package correlation

import "context"

// Strategy analyzes one correlation pass's Input and returns zero or more
// candidate Edges (phase12.md §22). Evaluate must never mutate Input,
// never perform a network/database request of its own, and never claim a
// relationship is definitely true — only the Evidence, Confidence, and
// Provenance it found (phase12.md §9/§10/§39). Mirrors
// internal/investigation.Rule and internal/ruleengine's own evaluation
// contracts exactly.
type Strategy interface {
	ID() string
	Name() string
	Description() string
	// Version identifies this strategy's logic revision (phase12.md §26)
	// — bumped whenever its matching logic materially changes, so a
	// persisted edge records exactly which revision produced it.
	Version() int
	Evaluate(ctx context.Context, input Input) ([]Edge, error)
}
