package correlation

import (
	"context"

	"github.com/google/uuid"

	"ai-surface-platform/internal/investigation"
)

// sameAssetScore is the point value phase9.md §36's worked example uses
// for "same asset".
const sameAssetScore = 30

// sameAssetRule links findings that affect the same asset (phase9.md
// §17) — e.g. an expired certificate, exposed API documentation, and
// missing HSTS all on example.com. It never claims these are one attack;
// it reports only that they share an asset, at a fixed, documented score.
type sameAssetRule struct{}

func (sameAssetRule) ID() string          { return "same_asset_findings" }
func (sameAssetRule) Name() string        { return "Same Asset" }
func (sameAssetRule) Description() string { return "Links findings that affect the same asset." }
func (sameAssetRule) Version() int        { return 1 }

func (r sameAssetRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	var out []investigation.Relationship
	forEachFindingPair(input.Findings, func(a, b investigation.FindingObservation) {
		if a.AssetID == b.AssetID && a.AssetID != uuid.Nil {
			detail := ""
			if asset, ok := input.AssetOf(a.AssetID); ok && asset.Hostname != "" {
				detail = "Shared asset: " + asset.Hostname + "."
			}
			out = append(out, newRelationship(a, b, investigation.RelationshipSameAsset, sameAssetScore,
				"same_asset", explanation("Both findings affect the same asset.", detail)))
		}
	})
	return out, nil
}
