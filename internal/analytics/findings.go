package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// FindingAnalytics implements phase14.md §9.
type FindingAnalytics struct {
	BySeverity     []analyticsrepo.NamedCount
	ByCategory     []analyticsrepo.NamedCount
	OverTime       []analyticsrepo.Bucket
	Open           int
	Resolved       int
	AffectedAssets []analyticsrepo.NamedCount // top N assets by finding count in range
}

// Findings implements phase14.md §9.
func (s *Service) Findings(ctx context.Context, targetID uuid.UUID, r TimeRange) (FindingAnalytics, error) {
	return cached(s, targetID, "findings", r, Filters{}, func() (FindingAnalytics, error) {
		var f FindingAnalytics
		var err error
		if f.BySeverity, err = s.repo.FindingsBySeverity(ctx, targetID, r.toRepo()); err != nil {
			return FindingAnalytics{}, err
		}
		if f.ByCategory, err = s.repo.FindingsByCategory(ctx, targetID, r.toRepo()); err != nil {
			return FindingAnalytics{}, err
		}
		if f.OverTime, err = s.repo.FindingsOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return FindingAnalytics{}, err
		}
		if f.Open, f.Resolved, err = s.repo.FindingsOpenVsResolved(ctx, targetID); err != nil {
			return FindingAnalytics{}, err
		}
		if f.AffectedAssets, err = s.repo.TopAffectedAssets(ctx, targetID, r.toRepo(), 10); err != nil {
			return FindingAnalytics{}, err
		}
		return f, nil
	})
}
