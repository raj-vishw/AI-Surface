package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// AIAnalytics implements phase14.md §17 — operational metrics only
// (requests, latency, tokens, failures, tool calls); it never exposes
// prompt content by default (phase14.md §17: "do not expose sensitive AI
// prompts by default") — no prompt/response text appears anywhere in
// this struct, only counts and identifiers already safe to display
// (task type, provider, tool name).
type AIAnalytics struct {
	RequestsOverTime []analyticsrepo.Bucket     `json:"requestsOverTime"`
	ByTaskType       []analyticsrepo.NamedCount `json:"byTaskType"`
	ByProvider       []analyticsrepo.NamedCount `json:"byProvider"`
	AverageLatencyMS float64                    `json:"averageLatencyMs"`
	InputTokens      int64                      `json:"inputTokens"`
	OutputTokens     int64                      `json:"outputTokens"`
	Failures         int                        `json:"failures"`
	ToolCallsByTool  []analyticsrepo.NamedCount `json:"toolCallsByTool"`
}

// AI implements phase14.md §17.
func (s *Service) AI(ctx context.Context, targetID uuid.UUID, r TimeRange) (AIAnalytics, error) {
	return cached(s, targetID, "ai", r, Filters{}, func() (AIAnalytics, error) {
		var a AIAnalytics
		var err error
		if a.RequestsOverTime, err = s.repo.AIRequestsOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return AIAnalytics{}, err
		}
		if a.ByTaskType, err = s.repo.AIRequestsByTaskType(ctx, targetID, r.toRepo()); err != nil {
			return AIAnalytics{}, err
		}
		if a.ByProvider, err = s.repo.AIRequestsByProvider(ctx, targetID, r.toRepo()); err != nil {
			return AIAnalytics{}, err
		}
		if a.AverageLatencyMS, err = s.repo.AIAverageLatencyMS(ctx, targetID, r.toRepo()); err != nil {
			return AIAnalytics{}, err
		}
		if a.InputTokens, a.OutputTokens, err = s.repo.AITokenTotals(ctx, targetID, r.toRepo()); err != nil {
			return AIAnalytics{}, err
		}
		if a.Failures, err = s.repo.AIFailureCount(ctx, targetID, r.toRepo()); err != nil {
			return AIAnalytics{}, err
		}
		if a.ToolCallsByTool, err = s.repo.AIToolCallsByTool(ctx, targetID, r.toRepo()); err != nil {
			return AIAnalytics{}, err
		}
		return a, nil
	})
}
