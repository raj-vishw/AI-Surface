package correlation

import (
	"context"

	"ai-recon-platform/internal/investigation"
)

const changeBasedScore = 25

// changeBasedRule links a finding to its own endpoint when that endpoint
// was itself newly observed within the same temporal window (phase9.md
// §20's worked example: /admin discovered in scan B, and scan B also
// produces a weak-authentication finding on it — "the endpoint was newly
// observed during the same scan in which the security finding was
// generated"). Named finding.go (rather than change.go) because it
// operates purely on Finding/Endpoint FirstSeen data already available on
// Input — no separate change-detection mechanism is introduced; Phase
// 7's own endpoint FirstSeen already IS the change signal this rule
// reads.
type changeBasedRule struct{}

func (changeBasedRule) ID() string   { return "endpoint_change_with_finding" }
func (changeBasedRule) Name() string { return "Change-Based Correlation" }
func (changeBasedRule) Description() string {
	return "Links a finding to its endpoint when the endpoint was itself newly observed around the same time."
}
func (changeBasedRule) Version() int { return 1 }

func (r changeBasedRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	window := input.Config.EffectiveTemporalWindow()
	var out []investigation.Relationship
	for _, f := range input.Findings {
		if f.EndpointID == nil {
			continue
		}
		ep, ok := input.EndpointOf(*f.EndpointID)
		if !ok || !withinWindow(ep.FirstSeen, f.FirstSeen, window) {
			continue
		}
		out = append(out, newEntityRelationship(f, investigation.EntityEndpoint, ep.ID,
			investigation.RelationshipChangeBased, changeBasedScore, "change_based",
			"The endpoint this finding affects ("+ep.Path+") was itself newly observed during the same scan window in which this finding was generated."))
	}
	return out, nil
}
