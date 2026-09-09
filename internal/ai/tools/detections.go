package tools

import (
	"context"

	"ai-surface-platform/internal/ai"
)

// getDetectionTool implements "get_detection" (phase13.md §28).
type getDetectionTool struct{ ds ai.DataSource }

// NewGetDetection returns the get_detection tool.
func NewGetDetection(ds ai.DataSource) ai.Tool { return getDetectionTool{ds: ds} }

func (getDetectionTool) Name() string { return "get_detection" }
func (getDetectionTool) Description() string {
	return "Retrieve one detection match by id, scoped to the calling session's target."
}
func (getDetectionTool) MaxResults() int { return 1 }

func (t getDetectionTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	id, err := ai.RequireString(args, "id")
	if err != nil {
		return ai.ToolResult{}, err
	}
	facts, err := t.ds.GetDetection(ctx, scope, id)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
