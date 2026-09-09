package strategies

import (
	"context"

	"ai-surface-platform/internal/correlation"
)

// networkStrategy links observations whose underlying asset shares an IP
// address (phase12.md §15) — uses Phase 2's already-recorded Asset.IP,
// never a new network scan of its own. Deliberately low-confidence and
// inferred: phase12.md §15 itself warns "same IP = same incident" is a
// false-correlation trap, since shared infrastructure (a CDN, a load
// balancer, shared hosting) can host many unrelated systems — the same
// caveat internal/investigation/correlation.sameServiceRule documents for
// Phase 9's identical signal.
type networkStrategy struct{}

// NewNetwork returns Phase 12's shared-IP correlation strategy.
func NewNetwork() correlation.Strategy { return networkStrategy{} }

func (networkStrategy) ID() string   { return "network" }
func (networkStrategy) Name() string { return "Shared Network/IP" }
func (networkStrategy) Description() string {
	return "Links observations whose assets share an IP address (weak signal, deliberately low-scored)."
}
func (networkStrategy) Version() int { return 1 }

func (networkStrategy) Evaluate(_ context.Context, input correlation.Input) ([]correlation.Edge, error) {
	var withIP []correlation.Observation
	for _, o := range input.Observations {
		if o.IP != "" {
			withIP = append(withIP, o)
		}
	}

	var out []correlation.Edge
	for i := 0; i < len(withIP); i++ {
		for j := i + 1; j < len(withIP); j++ {
			a, b := withIP[i], withIP[j]
			if a.IP != b.IP || a.AssetID == b.AssetID {
				continue // same_asset is asset.go's stronger, observed signal
			}
			out = append(out, correlation.Edge{
				Source:       correlation.NodeRef{Type: a.Type, ReferenceID: a.ReferenceID},
				Target:       correlation.NodeRef{Type: b.Type, ReferenceID: b.ReferenceID},
				Relationship: correlation.RelationshipAssociatedWith, Provenance: correlation.ProvenanceInferred,
				Confidence: correlation.ConfidenceLow,
				Evidence:   "Both observations' assets share IP address " + a.IP + ". Shared infrastructure (a CDN, load balancer, or shared host) can serve many unrelated systems, so this alone is weak evidence.",
			})
		}
	}
	return out, nil
}
