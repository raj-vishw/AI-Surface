package tools

import (
	"context"

	"ai-surface-platform/internal/ai"
)

// getTimelineTool implements "get_timeline" (phase13.md §28).
type getTimelineTool struct{ ds ai.DataSource }

// NewGetTimeline returns the get_timeline tool.
func NewGetTimeline(ds ai.DataSource) ai.Tool { return getTimelineTool{ds: ds} }

func (getTimelineTool) Name() string { return "get_timeline" }
func (getTimelineTool) Description() string {
	return "Retrieve the calling session's investigation timeline, chronologically, bounded by limit."
}
func (getTimelineTool) MaxResults() int { return ai.DefaultMaxTotalFacts }

func (t getTimelineTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	limit := ai.OptionalLimit(args, ai.DefaultMaxTotalFacts)
	facts, err := t.ds.GetTimeline(ctx, scope, limit)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
