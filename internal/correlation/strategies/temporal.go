// Package strategies implements Phase 12's built-in correlation
// Strategy set (phase12.md §11-21/§22) and RegisterAll, which registers
// every one of them into an internal/correlation.StrategyRegistry — the
// same split internal/investigation/correlation is for Phase 9's
// correlation.Registry, and internal/ruleengine/builtin is for Phase 11's
// rule engine.
package strategies

import (
	"context"
	"fmt"
	"sort"

	"ai-recon-platform/internal/correlation"
)

// temporalStrategy links observations first observed within a configured
// window of each other (phase12.md §11/§12/§13). Temporal proximity
// alone is never treated as implying a relationship — it is always
// inferred, always EdgeConfidenceLow, and its own explanation states the
// caveat explicitly (phase12.md §39). Uses a sort-then-sliding-window
// scan rather than comparing every pair (phase12.md §64/§95): observations
// are sorted by Timestamp once, and only neighbors within the configured
// window are ever compared, so the cost is O(n log n + k) rather than
// O(n^2) for a reasonably-spread evidence set.
type temporalStrategy struct{}

// NewTemporal returns Phase 12's temporal-proximity correlation strategy.
func NewTemporal() correlation.Strategy { return temporalStrategy{} }

func (temporalStrategy) ID() string   { return "temporal" }
func (temporalStrategy) Name() string { return "Temporal Proximity" }
func (temporalStrategy) Description() string {
	return "Links observations first observed within a configured time window of each other."
}
func (temporalStrategy) Version() int { return 1 }

func (temporalStrategy) Evaluate(_ context.Context, input correlation.Input) ([]correlation.Edge, error) {
	window := input.Config.EffectiveTemporalWindow()
	obs := append([]correlation.Observation(nil), input.Observations...)
	sort.Slice(obs, func(i, j int) bool { return obs[i].Timestamp.Before(obs[j].Timestamp) })

	var out []correlation.Edge
	for i := range obs {
		for j := i + 1; j < len(obs); j++ {
			gap := obs[j].Timestamp.Sub(obs[i].Timestamp)
			if gap > window {
				break // obs is sorted by time — nothing further out can be within window either
			}
			if obs[i].Type == obs[j].Type && obs[i].ReferenceID == obs[j].ReferenceID {
				continue
			}
			out = append(out, correlation.Edge{
				Source:       correlation.NodeRef{Type: obs[i].Type, ReferenceID: obs[i].ReferenceID},
				Target:       correlation.NodeRef{Type: obs[j].Type, ReferenceID: obs[j].ReferenceID},
				Relationship: correlation.RelationshipFollowedBy, Provenance: correlation.ProvenanceInferred,
				Confidence: correlation.ConfidenceLow,
				Evidence:   fmt.Sprintf("Both observations occurred within %s of each other. Temporal proximity alone is a weak, standalone signal — it does not imply a causal relationship.", window),
			})
		}
	}
	return out, nil
}
