package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-surface-platform/internal/repository/analytics"
)

// AssetAnalytics implements phase14.md §10.
type AssetAnalytics struct {
	Total        int                        `json:"total"`
	ByType       []analyticsrepo.NamedCount `json:"byType"`
	ByStatus     []analyticsrepo.NamedCount `json:"byStatus"`
	RiskCritical int                        `json:"riskCritical"`
	RiskHigh     int                        `json:"riskHigh"`
}

// Assets implements phase14.md §10.
func (s *Service) Assets(ctx context.Context, targetID uuid.UUID) (AssetAnalytics, error) {
	return cached(s, targetID, "assets", TimeRange{}, Filters{}, func() (AssetAnalytics, error) {
		var a AssetAnalytics
		var err error
		if a.Total, err = s.repo.CountAssets(ctx, targetID); err != nil {
			return AssetAnalytics{}, err
		}
		if a.ByType, err = s.repo.AssetsByType(ctx, targetID); err != nil {
			return AssetAnalytics{}, err
		}
		if a.ByStatus, err = s.repo.CountAssetsByStatus(ctx, targetID); err != nil {
			return AssetAnalytics{}, err
		}
		if a.RiskCritical, a.RiskHigh, err = s.repo.CountCriticalHighRiskAssets(ctx, targetID); err != nil {
			return AssetAnalytics{}, err
		}
		return a, nil
	})
}

// AttackSurfaceTrend implements phase14.md §11/§26 — reusing Phase 2's
// own FirstSeen/Status tracking rather than a new snapshot mechanism
// (phase14.md §75).
type AttackSurfaceTrend struct {
	NewAssets     []analyticsrepo.Bucket     `json:"newAssets"`
	RemovedAssets int                        `json:"removedAssets"`
	ByType        []analyticsrepo.NamedCount `json:"byType"`
}

// AttackSurface implements phase14.md §11/§26.
func (s *Service) AttackSurface(ctx context.Context, targetID uuid.UUID, r TimeRange) (AttackSurfaceTrend, error) {
	return cached(s, targetID, "attack_surface", r, Filters{}, func() (AttackSurfaceTrend, error) {
		var t AttackSurfaceTrend
		var err error
		if t.NewAssets, err = s.repo.NewAssetsOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return AttackSurfaceTrend{}, err
		}
		if t.RemovedAssets, err = s.repo.RemovedAssetsCount(ctx, targetID, r.toRepo()); err != nil {
			return AttackSurfaceTrend{}, err
		}
		if t.ByType, err = s.repo.AssetsByType(ctx, targetID); err != nil {
			return AttackSurfaceTrend{}, err
		}
		return t, nil
	})
}
