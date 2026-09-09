package tools

import (
	"context"

	"ai-surface-platform/internal/ai"
)

// getRiskTool implements "get_risk" (phase13.md §28).
type getRiskTool struct{ ds ai.DataSource }

// NewGetRisk returns the get_risk tool.
func NewGetRisk(ds ai.DataSource) ai.Tool { return getRiskTool{ds: ds} }

func (getRiskTool) Name() string { return "get_risk" }
func (getRiskTool) Description() string {
	return "Retrieve the latest risk score for one entity id, scoped to the calling session's target."
}
func (getRiskTool) MaxResults() int { return 1 }

func (t getRiskTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	id, err := ai.RequireString(args, "entity_id")
	if err != nil {
		return ai.ToolResult{}, err
	}
	facts, err := t.ds.GetRisk(ctx, scope, id)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
