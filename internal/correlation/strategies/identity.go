package strategies

import (
	"context"

	"github.com/google/uuid"

	"ai-recon-platform/internal/correlation"
)

// identityStrategy is phase12.md §14's "identity correlation" adapted to
// this platform's real architecture: ai-recon is an attack-surface
// reconnaissance tool with no user/account/session model, so there is no
// "failed login" / "successful login" event to correlate by username
// (phase12.md §14's own worked example assumes exactly that). What this
// platform does have is Phase 8's authentication Category on findings and
// Phase 11's rule.Category on detection matches — the closest honest
// analog to "identity-surface activity" available. This strategy links
// two authentication-category observations on the SAME asset, never
// merely because two identifiers look similar (phase12.md §14's explicit
// warning against that), since this platform has no identifier to compare
// in the first place — same-asset co-location is the only signal it can
// honestly claim.
type identityStrategy struct{}

// NewIdentity returns Phase 12's identity/authentication-surface
// correlation strategy.
func NewIdentity() correlation.Strategy { return identityStrategy{} }

func (identityStrategy) ID() string   { return "identity" }
func (identityStrategy) Name() string { return "Authentication Surface Co-location" }
func (identityStrategy) Description() string {
	return "Links authentication-category findings/detections on the same asset (this platform has no user/session model to correlate by identity directly)."
}
func (identityStrategy) Version() int { return 1 }

func (identityStrategy) Evaluate(_ context.Context, input correlation.Input) ([]correlation.Edge, error) {
	var authObs []correlation.Observation
	for _, o := range input.Observations {
		if o.Category == "authentication" && o.AssetID != uuid.Nil {
			authObs = append(authObs, o)
		}
	}

	var out []correlation.Edge
	for i := 0; i < len(authObs); i++ {
		for j := i + 1; j < len(authObs); j++ {
			a, b := authObs[i], authObs[j]
			if a.AssetID != b.AssetID || (a.Type == b.Type && a.ReferenceID == b.ReferenceID) {
				continue
			}
			out = append(out, correlation.Edge{
				Source:       correlation.NodeRef{Type: a.Type, ReferenceID: a.ReferenceID},
				Target:       correlation.NodeRef{Type: b.Type, ReferenceID: b.ReferenceID},
				Relationship: correlation.RelationshipAssociatedWith, Provenance: correlation.ProvenanceInferred,
				Confidence: correlation.ConfidenceLow,
				Evidence:   "Both observations are categorized as authentication-related and affect the same asset — worth reviewing together, though this does not by itself indicate a successful bypass or a shared user identity.",
			})
		}
	}
	return out, nil
}
