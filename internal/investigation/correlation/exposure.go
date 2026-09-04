package correlation

import (
	"context"

	"ai-recon-platform/internal/investigation"
)

const newAssetWithFindingScore = 20

// newAssetWithFindingRule flags a finding whose asset was itself first
// observed within the same temporal window as the finding (phase9.md
// §21's worked example: a new subdomain followed immediately by an
// exposed-API-documentation finding). Explicitly not a maliciousness
// claim — new assets routinely carry findings simply because they were
// just scanned for the first time.
type newAssetWithFindingRule struct{}

func (newAssetWithFindingRule) ID() string   { return "new_asset_with_finding" }
func (newAssetWithFindingRule) Name() string { return "New Asset With Finding" }
func (newAssetWithFindingRule) Description() string {
	return "Flags a finding whose asset was itself newly discovered around the same time."
}
func (newAssetWithFindingRule) Version() int { return 1 }

func (r newAssetWithFindingRule) Evaluate(_ context.Context, input investigation.Input) ([]investigation.Relationship, error) {
	window := input.Config.EffectiveTemporalWindow()
	var out []investigation.Relationship
	for _, f := range input.Findings {
		asset, ok := input.AssetOf(f.AssetID)
		if !ok || !withinWindow(asset.FirstSeen, f.FirstSeen, window) {
			continue
		}
		label := asset.Hostname
		if label == "" {
			label = asset.IP
		}
		out = append(out, newEntityRelationship(f, investigation.EntityAsset, asset.ID,
			investigation.RelationshipNewAssetFinding, newAssetWithFindingScore, "new_asset_with_finding",
			"This finding's asset ("+label+") was itself first observed around the same time as this finding — consistent with a newly discovered asset simply being scanned for the first time, not necessarily anything malicious."))
	}
	return out, nil
}
