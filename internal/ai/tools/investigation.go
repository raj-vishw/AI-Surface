package tools

import (
	"context"

	"ai-surface-platform/internal/ai"
)

// getInvestigationTool implements "get_investigation" (phase13.md §28).
type getInvestigationTool struct{ ds ai.DataSource }

// NewGetInvestigation returns the get_investigation tool.
func NewGetInvestigation(ds ai.DataSource) ai.Tool { return getInvestigationTool{ds: ds} }

func (getInvestigationTool) Name() string { return "get_investigation" }
func (getInvestigationTool) Description() string {
	return "Retrieve one investigation's own facts (status, severity, priority) by id, scoped to the calling session's target."
}
func (getInvestigationTool) MaxResults() int { return 1 }

func (t getInvestigationTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	id, err := ai.RequireString(args, "id")
	if err != nil {
		return ai.ToolResult{}, err
	}
	facts, err := t.ds.GetInvestigation(ctx, scope, id)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
