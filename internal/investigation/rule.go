package investigation

import "context"

// Rule analyzes one investigation's Input and returns zero or more
// candidate Relationships. Evaluate must never mutate Input, never
// perform a network/database request of its own, and never claim a
// relationship is definitely true — only the signals it found and the
// score they sum to (phase9.md §13/§14).
type Rule interface {
	ID() string
	Name() string
	Description() string
	// Version identifies this rule's logic revision (phase9.md §15) —
	// bumped whenever its scoring materially changes, so a persisted
	// relationship records exactly which revision produced it.
	Version() int
	Evaluate(ctx context.Context, input Input) ([]Relationship, error)
}
