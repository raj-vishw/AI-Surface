package analytics

import (
	"context"
	"sort"

	"github.com/google/uuid"

	analyticsrepo "ai-recon-platform/internal/repository/analytics"
)

// DetectionAnalytics implements phase14.md §8. MatchRate/AlertConversion/
// DismissalRate are computed per rule from actual matches/alerts/
// suppressions this platform recorded — never labeled a false-positive
// rate, since no ground-truth confirmation exists (phase14.md §8's own
// explicit instruction).
type DetectionAnalytics struct {
	MatchesOverTime []analyticsrepo.Bucket     `json:"matchesOverTime"`
	ByRule          []analyticsrepo.NamedCount `json:"byRule"`
	BySeverity      []analyticsrepo.NamedCount `json:"bySeverity"`
	EnabledRules    int                        `json:"enabledRules"`
	DisabledRules   int                        `json:"disabledRules"`
	// NoisyRules are the rules with the most matches in range, sorted
	// descending — an analyst signal, not an automatic "bad rule"
	// classification (phase14.md §30).
	NoisyRules []RuleRate `json:"noisyRules"`
}

// RuleRate is one rule's own match/alert/dismissal counters and derived
// rates for range r (phase14.md §8's "match rate", "alert conversion",
// "dismissal rate" — see docs/analytics/metrics.md for the exact
// formulas).
type RuleRate struct {
	Rule            string  `json:"rule"`
	Matches         int     `json:"matches"`
	Alerts          int     `json:"alerts"`
	Dismissed       int     `json:"dismissed"`
	AlertConversion float64 `json:"alertConversion"` // Alerts / Matches, 0 if Matches == 0
	DismissalRate   float64 `json:"dismissalRate"`   // Dismissed / Alerts, 0 if Alerts == 0
}

// Detections implements phase14.md §8.
func (s *Service) Detections(ctx context.Context, targetID uuid.UUID, r TimeRange) (DetectionAnalytics, error) {
	return cached(s, targetID, "detections", r, Filters{}, func() (DetectionAnalytics, error) {
		var d DetectionAnalytics
		var err error
		if d.MatchesOverTime, err = s.repo.DetectionMatchesOverTime(ctx, targetID, r.toRepo(), r.Interval); err != nil {
			return DetectionAnalytics{}, err
		}
		if d.ByRule, err = s.repo.MatchesByRule(ctx, targetID, r.toRepo()); err != nil {
			return DetectionAnalytics{}, err
		}
		if d.BySeverity, err = s.repo.MatchesBySeverity(ctx, targetID, r.toRepo()); err != nil {
			return DetectionAnalytics{}, err
		}
		if d.EnabledRules, d.DisabledRules, err = s.repo.RuleStatusCounts(ctx, targetID); err != nil {
			return DetectionAnalytics{}, err
		}
		conversion, err := s.repo.RuleAlertConversion(ctx, targetID, r.toRepo())
		if err != nil {
			return DetectionAnalytics{}, err
		}
		for name, c := range conversion {
			rate := RuleRate{Rule: name, Matches: c.Matches, Alerts: c.Alerts, Dismissed: c.Dismissed}
			if c.Matches > 0 {
				rate.AlertConversion = float64(c.Alerts) / float64(c.Matches)
			}
			if c.Alerts > 0 {
				rate.DismissalRate = float64(c.Dismissed) / float64(c.Alerts)
			}
			d.NoisyRules = append(d.NoisyRules, rate)
		}
		// Sort by match count descending, breaking ties alphabetically by
		// rule name — deterministic regardless of the source map's
		// iteration order.
		sort.Slice(d.NoisyRules, func(i, j int) bool {
			if d.NoisyRules[i].Matches != d.NoisyRules[j].Matches {
				return d.NoisyRules[i].Matches > d.NoisyRules[j].Matches
			}
			return d.NoisyRules[i].Rule < d.NoisyRules[j].Rule
		})
		return d, nil
	})
}
