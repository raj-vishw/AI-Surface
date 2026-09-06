package strategies

import (
	"context"

	"github.com/google/uuid"

	"ai-recon-platform/internal/correlation"
)

// assetStrategy links observations that already carry the SAME AssetID
// (phase12.md §16) — the platform's strongest, directly-OBSERVED signal
// (not inferred): a finding, a detection match, an endpoint observation,
// and an intelligence record referencing the same asset is a real
// foreign-key fact this platform already recorded, not a pattern this
// engine guessed at.
type assetStrategy struct{}

// NewAsset returns Phase 12's same-asset correlation strategy.
func NewAsset() correlation.Strategy { return assetStrategy{} }

func (assetStrategy) ID() string   { return "asset" }
func (assetStrategy) Name() string { return "Same Asset" }
func (assetStrategy) Description() string {
	return "Links observations that already reference the same asset — a directly observed relationship, not inferred."
}
func (assetStrategy) Version() int { return 1 }

func (assetStrategy) Evaluate(_ context.Context, input correlation.Input) ([]correlation.Edge, error) {
	var withAsset []correlation.Observation
	for _, o := range input.Observations {
		if o.AssetID != uuid.Nil {
			withAsset = append(withAsset, o)
		}
	}

	var out []correlation.Edge
	for i := 0; i < len(withAsset); i++ {
		for j := i + 1; j < len(withAsset); j++ {
			a, b := withAsset[i], withAsset[j]
			if a.AssetID != b.AssetID {
				continue
			}
			out = append(out, correlation.Edge{
				Source:       correlation.NodeRef{Type: a.Type, ReferenceID: a.ReferenceID},
				Target:       correlation.NodeRef{Type: b.Type, ReferenceID: b.ReferenceID},
				Relationship: correlation.RelationshipObservedOn, Provenance: correlation.ProvenanceObserved,
				Confidence: correlation.ConfidenceHigh,
				Evidence:   "Both observations reference asset " + a.AssetID.String() + " directly — an already-recorded relationship, not an inference.",
			})
		}
	}
	return out, nil
}
