package correlation

import (
	"context"

	"ai-recon-platform/internal/investigation"
)

// sameNetworkScore is deliberately low — phase9.md §39 explicitly warns
// "same IP = same incident" is a false-correlation trap, since shared
// infrastructure (a CDN, a load balancer, shared hosting) can host many
// unrelated systems. This rule alone can never cross the default
// threshold (60); it only ever contributes as one signal among several.
const sameNetworkScore = 15

// sameServiceRule links findings on different assets that share the same
// IP address (phase9.md §17's "same service"/§12's "same_network"). It
// carries an explicit caveat in its own explanation text rather than
// implying a relationship — verified directly by
// TestSameServiceRule_AloneNeverCrossesDefaultThreshold.
type sameServiceRule struct{}

func (sameServiceRule) ID() string   { return "same_service" }
func (sameServiceRule) Name() string { return "Same Network/Service" }
func (sameServiceRule) Description() string {
	return "Links findings on different assets sharing the same IP address (weak signal, deliberately low-scored)."
}
func (sameServiceRule) Version() int { return 1 }

func (r sameServiceRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	var out []investigation.Relationship
	forEachFindingPair(input.Findings, func(a, b investigation.FindingObservation) {
		if a.AssetID == b.AssetID {
			return // same_asset_findings already covers this, more strongly
		}
		assetA, okA := input.AssetOf(a.AssetID)
		assetB, okB := input.AssetOf(b.AssetID)
		if !okA || !okB || assetA.IP == "" || assetA.IP != assetB.IP {
			return
		}
		out = append(out, newRelationship(a, b, investigation.RelationshipSameService, sameNetworkScore,
			"same_network",
			"Both findings' assets share IP address "+assetA.IP+". Shared infrastructure (a CDN, load balancer, or shared host) can serve many unrelated systems, so this alone is weak evidence and is never sufficient by itself to confirm a relationship."))
	})
	return out, nil
}
