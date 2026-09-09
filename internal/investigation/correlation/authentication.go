package correlation

import (
	"context"

	"ai-surface-platform/internal/investigation"
)

const authCoLocationScore = 15

// authenticationColocationRule links two findings both categorized
// "authentication" on the same asset — a domain-specific refinement of
// same_asset_findings that calls out the specific, higher-attention
// category explicitly rather than leaving it implicit in a generic
// same-asset grouping. Informational: it never claims an authentication
// bypass or credential compromise, only that multiple authentication-
// surface observations exist together.
type authenticationColocationRule struct{}

func (authenticationColocationRule) ID() string   { return "authentication_colocation" }
func (authenticationColocationRule) Name() string { return "Authentication Finding Co-location" }
func (authenticationColocationRule) Description() string {
	return "Links two authentication-category findings on the same asset."
}
func (authenticationColocationRule) Version() int { return 1 }

func (r authenticationColocationRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	var out []investigation.Relationship
	forEachFindingPair(input.Findings, func(a, b investigation.FindingObservation) {
		if a.AssetID != b.AssetID || a.Category != "authentication" || b.Category != "authentication" {
			return
		}
		out = append(out, newRelationship(a, b, investigation.RelationshipAuthCoLocation, authCoLocationScore,
			"authentication_colocation",
			"Both findings are categorized as authentication-related and affect the same asset — worth reviewing together, though this does not by itself indicate a successful bypass or compromise."))
	})
	return out, nil
}
