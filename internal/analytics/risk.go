package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// RiskAnalytics implements phase14.md §6's risk-trend requirements —
// built entirely from Phase 10's own append-only risk_scores history, no
// new snapshot table (phase14.md §75: "if historical snapshots already
// exist, use them").
type RiskAnalytics struct {
	Trend        []analyticsrepo.RiskBucket
	Distribution []analyticsrepo.NamedCount // latest score per entity, bucketed by severity
}

// Risk implements phase14.md §6.
func (s *Service) Risk(ctx context.Context, targetID uuid.UUID, r TimeRange) (RiskAnalytics, error) {
	return cached(s, targetID, "risk", r, Filters{}, func() (RiskAnalytics, error) {
		trend, err := s.repo.RiskTrend(ctx, targetID, r.toRepo(), r.Interval)
		if err != nil {
			return RiskAnalytics{}, err
		}
		dist, err := s.repo.LatestRiskDistribution(ctx, targetID)
		if err != nil {
			return RiskAnalytics{}, err
		}
		return RiskAnalytics{Trend: trend, Distribution: dist}, nil
	})
}
