package correlation

import (
	"context"

	"ai-surface-platform/internal/investigation"
)

const sameEndpointScore = 30

// sameEndpointRule links findings affecting the same endpoint (phase9.md
// §18) — e.g. two findings both against /api/users.
type sameEndpointRule struct{}

func (sameEndpointRule) ID() string          { return "same_endpoint_findings" }
func (sameEndpointRule) Name() string        { return "Same Endpoint" }
func (sameEndpointRule) Description() string { return "Links findings that affect the same endpoint." }
func (sameEndpointRule) Version() int        { return 1 }

func (r sameEndpointRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	var out []investigation.Relationship
	forEachFindingPair(input.Findings, func(a, b investigation.FindingObservation) {
		if a.EndpointID == nil || b.EndpointID == nil || *a.EndpointID != *b.EndpointID {
			return
		}
		detail := ""
		if ep, ok := input.EndpointOf(*a.EndpointID); ok && ep.Path != "" {
			detail = "Shared endpoint: " + ep.Path + "."
		}
		out = append(out, newRelationship(a, b, investigation.RelationshipSameEndpoint, sameEndpointScore,
			"same_endpoint", explanation("Both findings affect the same endpoint.", detail)))
	})
	return out, nil
}
