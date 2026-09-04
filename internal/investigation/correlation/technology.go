package correlation

import (
	"context"

	"github.com/google/uuid"

	"ai-recon-platform/internal/investigation"
)

const sameTechnologyScore = 10

// technologyRule associates a finding with an already-fingerprinted
// technology belief on the same asset (phase9.md §19) — e.g. Phase 6
// identified nginx on this asset, and Phase 8 separately flagged an
// exposed server-version header on it. It links the two observations as
// evidence, never as a claim that the technology is exploitable.
type technologyRule struct{}

func (technologyRule) ID() string   { return "technology_correlation" }
func (technologyRule) Name() string { return "Technology Correlation" }
func (technologyRule) Description() string {
	return "Associates a finding with an already-fingerprinted technology on the same asset."
}
func (technologyRule) Version() int { return 1 }

func (r technologyRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	var out []investigation.Relationship
	for _, f := range input.Findings {
		for _, tech := range input.Technologies {
			if tech.AssetID != f.AssetID || tech.ID == uuid.Nil {
				continue
			}
			label := tech.Technology
			if tech.Version != "" {
				label += " " + tech.Version
			}
			out = append(out, newEntityRelationship(f, investigation.EntityTechnology, tech.ID,
				investigation.RelationshipSameTechnology, sameTechnologyScore, "same_technology",
				"This finding's asset was independently fingerprinted as running "+label+". This associates the two observations as evidence; it is not a claim that "+label+" is exploitable."))
		}
	}
	return out, nil
}
