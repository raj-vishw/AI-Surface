package investigation

import "github.com/google/uuid"

// EntityType mirrors internal/domain/investigation.EntityType — an
// independent copy for this package's zero-domain-dependency discipline
// (the same split internal/detection keeps from internal/domain/finding).
type EntityType string

// Recognized entity types.
const (
	EntityFinding    EntityType = "finding"
	EntityAsset      EntityType = "asset"
	EntityEndpoint   EntityType = "endpoint"
	EntityTechnology EntityType = "technology"
)

// RelationshipType names why two entities were correlated (phase9.md
// §12) — mirrors internal/domain/investigation.RelationshipType.
type RelationshipType string

// Recognized relationship types.
const (
	RelationshipSameAsset       RelationshipType = "same_asset"
	RelationshipSameEndpoint    RelationshipType = "same_endpoint"
	RelationshipSameDetector    RelationshipType = "same_detector"
	RelationshipTemporal        RelationshipType = "temporal_proximity"
	RelationshipSameTechnology  RelationshipType = "same_technology"
	RelationshipSameService     RelationshipType = "same_service"
	RelationshipChangeBased     RelationshipType = "change_based"
	RelationshipNewAssetFinding RelationshipType = "new_asset_with_finding"
	RelationshipAuthCoLocation  RelationshipType = "authentication_colocation"
)

// Confidence mirrors internal/domain/investigation.Confidence's
// five-level vocabulary.
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceVeryLow  Confidence = "very_low"
	ConfidenceLow      Confidence = "low"
	ConfidenceMedium   Confidence = "medium"
	ConfidenceHigh     Confidence = "high"
	ConfidenceVeryHigh Confidence = "very_high"
)

// ConfidenceForScore buckets a 0-100 correlation score into a Confidence
// level (phase9.md §36's "document the calculation" — this is the one
// place that mapping lives, never re-derived ad hoc per rule).
func ConfidenceForScore(score int) Confidence {
	switch {
	case score >= 90:
		return ConfidenceVeryHigh
	case score >= 70:
		return ConfidenceHigh
	case score >= 50:
		return ConfidenceMedium
	case score >= 25:
		return ConfidenceLow
	default:
		return ConfidenceVeryLow
	}
}

// Relationship is one rule's output for a pair of entities — the
// in-memory counterpart of internal/domain/investigation.Relationship,
// produced entirely from Input with no database access of its own.
type Relationship struct {
	SourceType EntityType
	SourceID   uuid.UUID
	TargetType EntityType
	TargetID   uuid.UUID

	Type RelationshipType

	// Score is the raw signal sum; Signals names each contributing
	// signal and its point value (phase9.md §36/§38) — never an opaque
	// number.
	Score       int
	Signals     map[string]int
	Explanation string

	RuleID      string
	RuleVersion int
}

// Key returns the deterministic identity two Relationship values share
// when they describe the same edge — used by MergeRelationships and by
// the service layer's upsert.
func (r Relationship) Key() string {
	return r.SourceType.String() + "|" + r.SourceID.String() + "|" +
		r.TargetType.String() + "|" + r.TargetID.String() + "|" +
		string(r.Type) + "|" + r.RuleID
}

// String satisfies fmt.Stringer for EntityType, used by Relationship.Key.
func (t EntityType) String() string { return string(t) }
