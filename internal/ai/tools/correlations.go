package tools

import (
	"context"

	"ai-recon-platform/internal/ai"
)

// getCorrelationTool implements "get_correlation" (phase13.md §28).
type getCorrelationTool struct{ ds ai.DataSource }

// NewGetCorrelation returns the get_correlation tool.
func NewGetCorrelation(ds ai.DataSource) ai.Tool { return getCorrelationTool{ds: ds} }

func (getCorrelationTool) Name() string { return "get_correlation" }
func (getCorrelationTool) Description() string {
	return "Retrieve one correlation's graph and attack chain (if any) by id, scoped to the calling session's target."
}
func (getCorrelationTool) MaxResults() int { return ai.DefaultMaxFactsPerType }

func (t getCorrelationTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	id, err := ai.RequireString(args, "id")
	if err != nil {
		return ai.ToolResult{}, err
	}
	facts, err := t.ds.GetCorrelation(ctx, scope, id)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
