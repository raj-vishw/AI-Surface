package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// IntelligenceAnalytics implements phase14.md §16. Every record here is
// already labeled with its own SourceType (Phase 10's "local" vs.
// external-provider distinction — see internal/domain/intelligence.
// Record.SourceType) — ByProvider surfaces that distinction directly
// rather than this layer inventing a second internal/external label.
type IntelligenceAnalytics struct {
	Total           int                        `json:"total"`
	ByIndicatorType []analyticsrepo.NamedCount `json:"byIndicatorType"`
	ByProvider      []analyticsrepo.NamedCount `json:"byProvider"`
	ByConfidence    []analyticsrepo.NamedCount `json:"byConfidence"`
	Expired         int                        `json:"expired"`
}

// Intelligence implements phase14.md §16.
func (s *Service) Intelligence(ctx context.Context, targetID uuid.UUID) (IntelligenceAnalytics, error) {
	return cached(s, targetID, "intelligence", TimeRange{}, Filters{}, func() (IntelligenceAnalytics, error) {
		var i IntelligenceAnalytics
		var err error
		if i.Total, err = s.repo.CountIntelligenceRecords(ctx, targetID); err != nil {
			return IntelligenceAnalytics{}, err
		}
		if i.ByIndicatorType, err = s.repo.IntelligenceByIndicatorType(ctx, targetID); err != nil {
			return IntelligenceAnalytics{}, err
		}
		if i.ByProvider, err = s.repo.IntelligenceByProvider(ctx, targetID); err != nil {
			return IntelligenceAnalytics{}, err
		}
		if i.ByConfidence, err = s.repo.IntelligenceByConfidence(ctx, targetID); err != nil {
			return IntelligenceAnalytics{}, err
		}
		if i.Expired, err = s.repo.ExpiredIntelligenceCount(ctx, targetID); err != nil {
			return IntelligenceAnalytics{}, err
		}
		return i, nil
	})
}
