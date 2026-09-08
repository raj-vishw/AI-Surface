package analytics

import (
	"context"

	"github.com/google/uuid"
)

// SecurityPosture is a single, documented derivation of Phase 10's own
// risk scores — never an independently invented metric (phase14.md §5).
//
// # Calculation
//
// Score = 100 - average(latest risk score per scored entity). Phase
// 10's risk_scores.score is already 0-100, where higher means riskier
// (internal/intelligence/risk); inverting it here is purely a display
// convention so a higher SecurityPosture.Score reads as "better," the
// same direction every other "posture"/"health" percentage in common use
// reads. No new risk computation happens here — this package never
// scores anything itself.
//
// # Inputs
//
// The most recent risk_scores row for every entity (asset, finding,
// investigation) this target has ever scored (Phase 10's own "latest
// wins" semantics — see RiskRepository.GetLatestRiskScore's identical
// rule). CriticalCount/HighCount are carried through unchanged from
// LatestRiskDistribution for context, not folded into the score a
// second time (avoiding double-counting the same underlying signal).
//
// # Weighting
//
// None beyond a simple, unweighted average across scored entities —
// deliberately so: this platform has no defined business-criticality
// weighting scheme beyond the optional, analyst-set AssetCriticality
// Phase 10 already factors into each individual risk score, so
// reintroducing a second weighting here would double-apply it.
//
// # Limitations
//
// This is not an objective measure of security (phase14.md §5's own
// instruction) — it reflects only what this platform has itself
// observed and scored; an unscored entity (no findings ever attached, no
// risk calculation ever run) contributes nothing, so a target with very
// little collected evidence can show a misleadingly high score. Always
// review ScoredEntities alongside Score before drawing any conclusion.
type SecurityPosture struct {
	Score          float64 `json:"score"`
	ScoredEntities int     `json:"scoredEntities"`
	CriticalCount  int     `json:"criticalCount"`
	HighCount      int     `json:"highCount"`
}

// Posture implements phase14.md §5.
func (s *Service) Posture(ctx context.Context, targetID uuid.UUID) (SecurityPosture, error) {
	return cached(s, targetID, "posture", TimeRange{}, Filters{}, func() (SecurityPosture, error) {
		avg, n, err := s.repo.LatestRiskAverage(ctx, targetID)
		if err != nil {
			return SecurityPosture{}, err
		}
		dist, err := s.repo.LatestRiskDistribution(ctx, targetID)
		if err != nil {
			return SecurityPosture{}, err
		}
		p := SecurityPosture{Score: 100 - avg, ScoredEntities: n}
		for _, d := range dist {
			switch d.Name {
			case "critical":
				p.CriticalCount = d.Count
			case "high":
				p.HighCount = d.Count
			}
		}
		if n == 0 {
			p.Score = 0 // no scored entities: an honest "unknown," never a fabricated perfect 100
		}
		return p, nil
	})
}
