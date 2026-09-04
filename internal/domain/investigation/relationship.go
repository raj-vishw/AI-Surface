package investigation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// RelationshipType names why two entities were correlated (phase9.md
// §12). Deliberately a closed, named vocabulary — never a bare
// "related: true" (phase9.md §35).
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

var validRelationshipTypes = map[RelationshipType]bool{
	RelationshipSameAsset: true, RelationshipSameEndpoint: true, RelationshipSameDetector: true,
	RelationshipTemporal: true, RelationshipSameTechnology: true, RelationshipSameService: true,
	RelationshipChangeBased: true, RelationshipNewAssetFinding: true, RelationshipAuthCoLocation: true,
}

// Valid reports whether t is a recognized relationship type.
func (t RelationshipType) Valid() bool { return validRelationshipTypes[t] }

// RelationshipStatus distinguishes an automatically-scored relationship
// that cleared the configured threshold (Confirmed) from one that did not
// but is still worth surfacing to an analyst (Candidate — phase9.md §37).
// Neither ever means "definitely true": see Relationship.Explanation and
// Inferred, which together make clear this is always the engine's
// interpretation, not an observed fact (phase9.md §84).
type RelationshipStatus string

// Recognized relationship statuses.
const (
	RelationshipCandidate RelationshipStatus = "candidate"
	RelationshipConfirmed RelationshipStatus = "confirmed"
)

var validRelationshipStatuses = map[RelationshipStatus]bool{
	RelationshipCandidate: true, RelationshipConfirmed: true,
}

// Valid reports whether s is a recognized relationship status.
func (s RelationshipStatus) Valid() bool { return validRelationshipStatuses[s] }

// Relationship is one edge the correlation engine (or an analyst,
// manually) recorded between two entities within an investigation
// (phase9.md §23). Always carries an Explanation and the individual
// Signals that produced Score — never an opaque number (phase9.md
// §36/§38).
type Relationship struct {
	ID              uuid.UUID
	InvestigationID uuid.UUID

	SourceType EntityType
	SourceID   uuid.UUID
	TargetType EntityType
	TargetID   uuid.UUID

	Type   RelationshipType
	Status RelationshipStatus

	// Score is the raw signal sum (phase9.md §36's worked example,
	// "same asset: +30, same endpoint: +30, ..."), documented per-rule in
	// internal/investigation/correlation. Not a probability — see
	// Confidence.
	Score int
	// Confidence buckets Score using the same five-level vocabulary
	// investigation.Confidence uses elsewhere in this package, never
	// claimed as a statistical probability (phase9.md §36).
	Confidence Confidence

	Explanation string
	// Signals names each contributing rule and its point value (phase9.md
	// §38's explainability requirement) — e.g. {"same_asset": 30,
	// "temporal_proximity": 20}.
	Signals map[string]int

	RuleID      string
	RuleVersion int

	CreatedAt time.Time
}

// Validate checks that r is internally consistent.
func (r Relationship) Validate() error {
	var errs validation.Errors

	if r.InvestigationID == uuid.Nil {
		errs = errs.Add("investigation_id", "must not be empty")
	}
	if !r.SourceType.Valid() {
		errs = errs.Add("source_type", "must be a recognized entity type")
	}
	if r.SourceID == uuid.Nil {
		errs = errs.Add("source_id", "must not be empty")
	}
	if !r.TargetType.Valid() {
		errs = errs.Add("target_type", "must be a recognized entity type")
	}
	if r.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !r.Type.Valid() {
		errs = errs.Add("type", "must be a recognized relationship type")
	}
	if !r.Status.Valid() {
		errs = errs.Add("status", "must be a recognized relationship status")
	}
	if !r.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if strings.TrimSpace(r.Explanation) == "" {
		errs = errs.Add("explanation", "must not be empty")
	}
	if strings.TrimSpace(r.RuleID) == "" {
		errs = errs.Add("rule_id", "must not be empty")
	}

	return errs.ErrOrNil()
}
