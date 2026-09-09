package strategies

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"ai-surface-platform/internal/correlation"
)

// detectionStrategy links two DIFFERENT Phase 11 detection rules that
// both fired on the same asset, in chronological order (phase12.md §18's
// worked example: repeated authentication failures → successful login →
// privilege change). Each underlying DetectionMatch is preserved
// independently (phase12.md §18's "the system must preserve each
// detection independently") — this strategy only adds an edge between
// them, it never merges or replaces either match.
type detectionStrategy struct{}

// NewDetection returns Phase 12's cross-rule detection correlation
// strategy.
func NewDetection() correlation.Strategy { return detectionStrategy{} }

func (detectionStrategy) ID() string   { return "detection" }
func (detectionStrategy) Name() string { return "Cross-Rule Detection Sequence" }
func (detectionStrategy) Description() string {
	return "Links detection matches from different rules on the same asset, ordered chronologically."
}
func (detectionStrategy) Version() int { return 1 }

func (detectionStrategy) Evaluate(_ context.Context, input correlation.Input) ([]correlation.Edge, error) {
	byAsset := map[uuid.UUID][]correlation.Observation{}
	for _, o := range input.Observations {
		if o.Type == correlation.NodeDetectionMatch && o.AssetID != uuid.Nil {
			byAsset[o.AssetID] = append(byAsset[o.AssetID], o)
		}
	}

	var out []correlation.Edge
	for _, matches := range byAsset {
		sort.Slice(matches, func(i, j int) bool { return matches[i].Timestamp.Before(matches[j].Timestamp) })
		for i := 0; i < len(matches); i++ {
			for j := i + 1; j < len(matches); j++ {
				a, b := matches[i], matches[j]
				if a.RuleID == b.RuleID {
					continue // repeated firings of the same rule are the rule's own dedup concern, not a cross-rule sequence
				}
				out = append(out, correlation.Edge{
					Source:       correlation.NodeRef{Type: a.Type, ReferenceID: a.ReferenceID},
					Target:       correlation.NodeRef{Type: b.Type, ReferenceID: b.ReferenceID},
					Relationship: correlation.RelationshipFollowedBy, Provenance: correlation.ProvenanceInferred,
					Confidence: correlation.ConfidenceMedium,
					Evidence:   "Two different detection rules fired on the same asset, in chronological order — each match's own explanation remains the authoritative account of why it fired individually.",
				})
			}
		}
	}
	return out, nil
}
