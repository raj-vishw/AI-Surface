package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// AlertAnalytics implements phase14.md §7.
type AlertAnalytics struct {
	OverTime   []analyticsrepo.Bucket     `json:"overTime"`
	BySeverity []analyticsrepo.NamedCount `json:"bySeverity"`
	ByStatus   []analyticsrepo.NamedCount `json:"byStatus"`
	ByRule     []analyticsrepo.NamedCount `json:"byRule"`
}

// Alerts implements phase14.md §7. Filters are not yet applied to the
// breakdowns themselves (each breakdown already IS the requested
// dimension); a future phase adding a combined severity+status query
// would extend, not replace, this signature.
func (s *Service) Alerts(ctx context.Context, targetID uuid.UUID, r TimeRange) (AlertAnalytics, error) {
	return cached(s, targetID, "alerts", r, Filters{}, func() (AlertAnalytics, error) {
		var a AlertAnalytics
		var err error
		if a.OverTime, err = s.repo.AlertsOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return AlertAnalytics{}, err
		}
		if a.BySeverity, err = s.repo.AlertsBySeverity(ctx, targetID, r.toRepo()); err != nil {
			return AlertAnalytics{}, err
		}
		if a.ByStatus, err = s.repo.AlertsByStatus(ctx, targetID, r.toRepo()); err != nil {
			return AlertAnalytics{}, err
		}
		if a.ByRule, err = s.repo.AlertsByRule(ctx, targetID, r.toRepo()); err != nil {
			return AlertAnalytics{}, err
		}
		return a, nil
	})
}
