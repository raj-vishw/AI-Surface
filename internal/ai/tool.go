package ai

import (
	"context"
	"fmt"
)

// ToolScope pins every tool call to exactly one target — this platform's
// authorization boundary (phase13.md §30: "the model cannot bypass RBAC";
// this platform has no RBAC, so TargetID scoping is the boundary that
// exists, the same adaptation every prior phase's own report documents).
// A tool implementation must never return data outside Scope.TargetID
// (and, when set, Scope.InvestigationID) regardless of what arguments it
// is called with.
type ToolScope struct {
	TargetID        string
	InvestigationID string // empty when the calling session is not investigation-scoped
	// UserID identifies the analyst on whose behalf this call runs — a
	// plain identifier, not an authenticated principal (see
	// internal/domain/ai's package doc comment) — carried through purely
	// for audit attribution.
	UserID string
}

// ToolArgs is a small, validated argument bag — always built from
// already-typed values (never raw untrusted JSON handed through
// unchecked), so a Tool's own Execute can assume its declared shape.
type ToolArgs map[string]any

// ToolResult is what a Tool returns — Facts ready to fold into a Context,
// bounded by MaxResults regardless of how much matching data actually
// exists.
type ToolResult struct {
	Facts     []Fact
	Truncated bool
}

// DataSource is the only way a Tool ever touches real platform data — an
// injected boundary implemented by internal/service/ai against the real
// repositories, exactly mirroring how internal/correlation/strategies
// operates only on Observation values assembled by the service layer
// rather than importing any repository package itself. This keeps every
// Tool here engine-pure, unit-testable with a fake DataSource, and
// structurally read-only: DataSource has no method that could mutate
// anything (phase13.md §31).
type DataSource interface {
	GetInvestigation(ctx context.Context, scope ToolScope, id string) ([]Fact, error)
	GetAlert(ctx context.Context, scope ToolScope, id string) ([]Fact, error)
	GetDetection(ctx context.Context, scope ToolScope, id string) ([]Fact, error)
	GetCorrelation(ctx context.Context, scope ToolScope, id string) ([]Fact, error)
	GetTimeline(ctx context.Context, scope ToolScope, limit int) ([]Fact, error)
	GetFindings(ctx context.Context, scope ToolScope, limit int) ([]Fact, error)
	GetAssets(ctx context.Context, scope ToolScope, limit int) ([]Fact, error)
	GetIntelligence(ctx context.Context, scope ToolScope, limit int) ([]Fact, error)
	GetRisk(ctx context.Context, scope ToolScope, entityID string) ([]Fact, error)
}

// Tool is one read-only, allowlisted AI capability (phase13.md §28-33).
type Tool interface {
	Name() string
	Description() string
	// MaxResults bounds how many Facts one call may ever return
	// (phase13.md §33) — enforced again by Executor regardless of what an
	// individual Tool implementation does internally.
	MaxResults() int
	Execute(ctx context.Context, scope ToolScope, args ToolArgs) (ToolResult, error)
}

// RequireString extracts a required, non-empty string argument, or an
// error identifying exactly which argument was invalid (phase13.md §32:
// "reject invalid... arguments").
func RequireString(args ToolArgs, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("argument %q must be a non-empty string", key)
	}
	return s, nil
}

// OptionalLimit extracts an optional integer "limit" argument, clamped to
// [1, maxAllowed] — never unbounded (phase13.md §33).
func OptionalLimit(args ToolArgs, maxAllowed int) int {
	if maxAllowed <= 0 {
		maxAllowed = 20
	}
	v, ok := args["limit"]
	if !ok {
		return maxAllowed
	}
	n, ok := v.(int)
	if !ok || n <= 0 {
		return maxAllowed
	}
	if n > maxAllowed {
		return maxAllowed
	}
	return n
}
