package analytics

import (
	"context"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// CorrelationAnalytics implements phase14.md §12.
type CorrelationAnalytics struct {
	OverTime     []analyticsrepo.Bucket
	BySeverity   []analyticsrepo.NamedCount
	ByConfidence []analyticsrepo.NamedCount
	ByStatus     []analyticsrepo.NamedCount
	ByStrategy   []analyticsrepo.NamedCount
}

// Correlations implements phase14.md §12.
func (s *Service) Correlations(ctx context.Context, targetID uuid.UUID, r TimeRange) (CorrelationAnalytics, error) {
	return cached(s, targetID, "correlations", r, Filters{}, func() (CorrelationAnalytics, error) {
		var c CorrelationAnalytics
		var err error
		if c.OverTime, err = s.repo.CorrelationsOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return CorrelationAnalytics{}, err
		}
		if c.BySeverity, err = s.repo.CorrelationsBySeverity(ctx, targetID, r.toRepo()); err != nil {
			return CorrelationAnalytics{}, err
		}
		if c.ByConfidence, err = s.repo.CorrelationsByConfidence(ctx, targetID, r.toRepo()); err != nil {
			return CorrelationAnalytics{}, err
		}
		if c.ByStatus, err = s.repo.CorrelationsByStatus(ctx, targetID, r.toRepo()); err != nil {
			return CorrelationAnalytics{}, err
		}
		if c.ByStrategy, err = s.repo.CorrelationsByStrategy(ctx, targetID, r.toRepo()); err != nil {
			return CorrelationAnalytics{}, err
		}
		return c, nil
	})
}

// AttackChainAnalytics implements phase14.md §13 — never implies every
// chain is a confirmed attack (phase14.md §13's own instruction);
// "IncompleteChains" measures chains whose stage count is below the
// platform's 9-stage vocabulary, not a judgment about the underlying
// activity.
type AttackChainAnalytics struct {
	OverTime     []analyticsrepo.Bucket
	BySeverity   []analyticsrepo.NamedCount
	ByConfidence []analyticsrepo.NamedCount
	CommonStages []analyticsrepo.NamedCount
}

// AttackChains implements phase14.md §13.
func (s *Service) AttackChains(ctx context.Context, targetID uuid.UUID, r TimeRange) (AttackChainAnalytics, error) {
	return cached(s, targetID, "attack_chains", r, Filters{}, func() (AttackChainAnalytics, error) {
		var a AttackChainAnalytics
		var err error
		if a.OverTime, err = s.repo.AttackChainsOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return AttackChainAnalytics{}, err
		}
		if a.BySeverity, err = s.repo.AttackChainsBySeverity(ctx, targetID, r.toRepo()); err != nil {
			return AttackChainAnalytics{}, err
		}
		if a.ByConfidence, err = s.repo.AttackChainsByConfidence(ctx, targetID, r.toRepo()); err != nil {
			return AttackChainAnalytics{}, err
		}
		if a.CommonStages, err = s.repo.CommonAttackStages(ctx, targetID, r.toRepo()); err != nil {
			return AttackChainAnalytics{}, err
		}
		return a, nil
	})
}
