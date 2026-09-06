package ai

import (
	"context"
	"time"
)

// ToolCallRecord is what Executor hands to an audit sink after every call
// — success, failure, or denial (phase13.md §34). internal/service/ai
// turns this into an internal/domain/ai.ToolCall row.
type ToolCallRecord struct {
	Tool          string
	Scope         ToolScope
	Arguments     ToolArgs
	Status        string // "success" | "error" | "denied"
	ResultSummary string
	Error         string
	Duration      time.Duration
}

// AuditFunc records one ToolCallRecord — implemented by
// internal/service/ai against internal/repository/ai.
type AuditFunc func(ToolCallRecord)

// Executor is the only path through which a Tool is ever called — it
// enforces the allowlist, per-call timeout, and result-size cap uniformly
// regardless of what an individual Tool does, and always audits, even on
// denial or failure (phase13.md §29-34).
type Executor struct {
	registry *ToolRegistry
	audit    AuditFunc
	// ToolTimeout bounds every individual tool call (phase13.md §33/§56).
	ToolTimeout time.Duration
}

// NewExecutor returns an Executor. audit may be nil (no-op) — useful for
// tests that don't care about the audit trail.
func NewExecutor(registry *ToolRegistry, audit AuditFunc, toolTimeout time.Duration) *Executor {
	if audit == nil {
		audit = func(ToolCallRecord) {}
	}
	if toolTimeout <= 0 {
		toolTimeout = 5 * time.Second
	}
	return &Executor{registry: registry, audit: audit, ToolTimeout: toolTimeout}
}

// Call executes name with args under scope, always within ToolTimeout,
// always auditing the outcome.
func (e *Executor) Call(ctx context.Context, name string, scope ToolScope, args ToolArgs) (ToolResult, error) {
	start := time.Now()

	tool, err := e.registry.Get(name)
	if err != nil {
		e.audit(ToolCallRecord{Tool: name, Scope: scope, Arguments: args, Status: "denied", Error: err.Error(), Duration: time.Since(start)})
		return ToolResult{}, err
	}

	callCtx, cancel := context.WithTimeout(ctx, e.ToolTimeout)
	defer cancel()

	result, err := tool.Execute(callCtx, scope, args)
	if err != nil {
		e.audit(ToolCallRecord{Tool: name, Scope: scope, Arguments: args, Status: "error", Error: err.Error(), Duration: time.Since(start)})
		return ToolResult{}, err
	}

	if maxResults := tool.MaxResults(); maxResults > 0 && len(result.Facts) > maxResults {
		result.Facts = result.Facts[:maxResults]
		result.Truncated = true
	}

	e.audit(ToolCallRecord{
		Tool: name, Scope: scope, Arguments: args, Status: "success",
		ResultSummary: resultSummary(result), Duration: time.Since(start),
	})
	return result, nil
}

func resultSummary(r ToolResult) string {
	if r.Truncated {
		return "returned facts (truncated to the configured maximum)"
	}
	return "returned facts"
}
