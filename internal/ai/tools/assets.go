package tools

import (
	"context"

	"ai-surface-platform/internal/ai"
)

// getAssetsTool implements "get_assets" (phase13.md §28).
type getAssetsTool struct{ ds ai.DataSource }

// NewGetAssets returns the get_assets tool.
func NewGetAssets(ds ai.DataSource) ai.Tool { return getAssetsTool{ds: ds} }

func (getAssetsTool) Name() string { return "get_assets" }
func (getAssetsTool) Description() string {
	return "Retrieve assets for the calling session's target, bounded by limit."
}
func (getAssetsTool) MaxResults() int { return ai.DefaultMaxFactsPerType }

func (t getAssetsTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	limit := ai.OptionalLimit(args, ai.DefaultMaxFactsPerType)
	facts, err := t.ds.GetAssets(ctx, scope, limit)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
