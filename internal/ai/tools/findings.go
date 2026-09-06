package tools

import (
	"context"

	"ai-recon-platform/internal/ai"
)

// getFindingsTool implements "get_findings" (phase13.md §28).
type getFindingsTool struct{ ds ai.DataSource }

// NewGetFindings returns the get_findings tool.
func NewGetFindings(ds ai.DataSource) ai.Tool { return getFindingsTool{ds: ds} }

func (getFindingsTool) Name() string { return "get_findings" }
func (getFindingsTool) Description() string {
	return "Retrieve findings for the calling session's target, bounded by limit."
}
func (getFindingsTool) MaxResults() int { return ai.DefaultMaxFactsPerType }

func (t getFindingsTool) Execute(ctx context.Context, scope ai.ToolScope, args ai.ToolArgs) (ai.ToolResult, error) {
	limit := ai.OptionalLimit(args, ai.DefaultMaxFactsPerType)
	facts, err := t.ds.GetFindings(ctx, scope, limit)
	if err != nil {
		return ai.ToolResult{}, err
	}
	return ai.ToolResult{Facts: facts}, nil
}
