package correlation

import (
	"context"
	"fmt"

	"ai-recon-platform/internal/investigation"
)

const temporalProximityScore = 20

// temporalProximityRule links findings first observed within a
// configurable window of each other (phase9.md §16). Temporal proximity
// alone is never treated as implying malicious activity — it is one
// signal among several, deliberately scored lower than same_asset/
// same_endpoint (phase9.md §16/§39).
type temporalProximityRule struct{}

func (temporalProximityRule) ID() string   { return "temporal_proximity" }
func (temporalProximityRule) Name() string { return "Temporal Proximity" }
func (temporalProximityRule) Description() string {
	return "Links findings first observed within a configured time window of each other."
}
func (temporalProximityRule) Version() int { return 1 }

func (r temporalProximityRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	window := input.Config.EffectiveTemporalWindow()
	var out []investigation.Relationship
	forEachFindingPair(input.Findings, func(a, b investigation.FindingObservation) {
		if !withinWindow(a.FirstSeen, b.FirstSeen, window) {
			return
		}
		out = append(out, newRelationship(a, b, investigation.RelationshipTemporal, temporalProximityScore,
			"temporal_proximity",
			fmt.Sprintf("Both findings were first observed within %s of each other. This is a weak, standalone signal — temporal proximity alone does not imply a relationship.", window)))
	})
	return out, nil
}
