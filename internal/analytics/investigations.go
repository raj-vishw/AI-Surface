package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// InvestigationAnalytics implements phase14.md §14 and, since this
// platform consolidates Incident into Investigation (the same Phase 9
// design decision Phase 11/12/13 already reused — see internal/domain/
// investigation's own package doc comment), also serves phase14.md
// §15's incident analytics: there is no second, parallel "incidents"
// table to aggregate separately.
type InvestigationAnalytics struct {
	OpenedOverTime      []analyticsrepo.Bucket     `json:"openedOverTime"`
	ClosedOverTime      []analyticsrepo.Bucket     `json:"closedOverTime"`
	BySeverity          []analyticsrepo.NamedCount `json:"bySeverity"`
	ByStatus            []analyticsrepo.NamedCount `json:"byStatus"`
	Active              int                        `json:"active"`
	MeanDurationSeconds float64                    `json:"meanDurationSeconds"`
	ClosedCount         int                        `json:"closedCount"`
}

// Investigations implements phase14.md §14/§15.
func (s *Service) Investigations(ctx context.Context, targetID uuid.UUID, r TimeRange) (InvestigationAnalytics, error) {
	return cached(s, targetID, "investigations", r, Filters{}, func() (InvestigationAnalytics, error) {
		var i InvestigationAnalytics
		var err error
		if i.OpenedOverTime, err = s.repo.InvestigationsOpenedOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return InvestigationAnalytics{}, err
		}
		if i.ClosedOverTime, err = s.repo.InvestigationsClosedOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return InvestigationAnalytics{}, err
		}
		if i.BySeverity, err = s.repo.InvestigationsBySeverity(ctx, targetID, r.toRepo()); err != nil {
			return InvestigationAnalytics{}, err
		}
		if i.ByStatus, err = s.repo.InvestigationsByStatus(ctx, targetID, r.toRepo()); err != nil {
			return InvestigationAnalytics{}, err
		}
		if i.Active, err = s.repo.CountActiveInvestigations(ctx, targetID); err != nil {
			return InvestigationAnalytics{}, err
		}
		if i.MeanDurationSeconds, i.ClosedCount, err = s.repo.MeanInvestigationDurationSeconds(ctx, targetID, r.toRepo()); err != nil {
			return InvestigationAnalytics{}, err
		}
		return i, nil
	})
}
