package tools

import (
	"context"

	"ai-surface-platform/internal/ai"
)

// getIntelligenceTool implements "get_intelligence" (phase13.md §28).
type getIntelligenceTool struct{ ds ai.DataSource }

// NewGetIntelligence returns the get_intelligence tool.
func NewGetIntelligence(ds ai.DataSource) ai.Tool { return getIntelligenceTool{ds: ds} }

func (getIntelligenceTool) Name() string { return "get_intelligence" }
func (getIntelligenceTool) Description() string {
	return "Retrieve threat-intelligence records for the calling session's target, bounded by limit."
}
func (getIntelligenceTool) MaxResults() int { return ai.DefaultMaxFactsPerType }

func (t getIntelligenceTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	limit := ai.OptionalLimit(args, ai.DefaultMaxFactsPerType)
	facts, err := t.ds.GetIntelligence(ctx, scope, limit)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
