package tools

import (
	"context"

	"ai-recon-platform/internal/ai"
)

// getAlertTool implements "get_alert" (phase13.md §28).
type getAlertTool struct{ ds ai.DataSource }

// NewGetAlert returns the get_alert tool.
func NewGetAlert(ds ai.DataSource) ai.Tool { return getAlertTool{ds: ds} }

func (getAlertTool) Name() string { return "get_alert" }
func (getAlertTool) Description() string {
	return "Retrieve one alert by id, scoped to the calling session's target."
}
func (getAlertTool) MaxResults() int { return 1 }

func (t getAlertTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	id, err := ai.RequireString(args, "id")
	if err != nil {
		return ai.ToolResult{}, err
	}
	facts, err := t.ds.GetAlert(ctx, scope, id)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
