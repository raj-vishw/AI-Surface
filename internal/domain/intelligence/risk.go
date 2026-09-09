package intelligence

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// ModelVersionV1 is the current, and so far only, risk model version
// (phase10.md §43). A calculated RiskScore always records exactly which
// version produced it so historical scores remain interpretable even if
// the model changes (phase10.md §45/§46).
const ModelVersionV1 = "v1"

// EntityType names what kind of thing a RiskScore was calculated for.
// Deliberately its own small type rather than an import of
// internal/domain/asset.Type/finding-scope/investigation.EntityType — see
// package doc comment.
type EntityType string

// Recognized risk entity types.
const (
	EntityAsset         EntityType = "asset"
	EntityFinding       EntityType = "finding"
	EntityInvestigation EntityType = "investigation"
)

var validEntityTypes = map[EntityType]bool{
	EntityAsset: true, EntityFinding: true, EntityInvestigation: true,
}

// Valid reports whether t is a recognized risk entity type.
func (t EntityType) Valid() bool { return validEntityTypes[t] }

// RiskSeverityForScore buckets a 0-100 score into a named severity —
// documented, fixed boundaries (phase10.md §41's worked example groups
// scores in the 70s as "High").
func RiskSeverityForScore(score int) Severity {
	switch {
	case score >= 75:
		return SeverityCritical
	case score >= 50:
		return SeverityHigh
	case score >= 25:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// RiskFactor is one named, scored contributor to a RiskScore — every
// score must explain itself (phase10.md §41): "High-severity finding:
// +30" is a RiskFactor{Name: "high_severity_finding", Points: 30, ...}.
type RiskFactor struct {
	Name        string
	Points      int
	Description string
}

// RiskScore is one calculated risk assessment for an entity (asset,
// finding, or investigation), fully explainable and versioned
// (phase10.md §33/§41/§43). A RiskScore row is never overwritten — a
// recalculation inserts a new row, preserving history (phase10.md §45/
// §46).
type RiskScore struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	EntityType EntityType
	EntityID   uuid.UUID

	// Score is clamped to [0, 100] by construction — see
	// internal/intelligence/risk.Scorer (phase10.md §42).
	Score      int
	Severity   Severity
	Confidence Confidence

	ModelVersion string
	Factors      []RiskFactor
	Explanation  string

	CalculatedAt time.Time
	CreatedAt    time.Time
}

// Validate checks that r is internally consistent.
func (r RiskScore) Validate() error {
	var errs validation.Errors

	if r.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !r.EntityType.Valid() {
		errs = errs.Add("entity_type", "must be a recognized risk entity type")
	}
	if r.EntityID == uuid.Nil {
		errs = errs.Add("entity_id", "must not be empty")
	}
	if r.Score < 0 || r.Score > 100 {
		errs = errs.Add("score", "must be between 0 and 100")
	}
	if !r.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !r.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if r.ModelVersion == "" {
		errs = errs.Add("model_version", "must not be empty")
	}
	if r.CalculatedAt.IsZero() {
		errs = errs.Add("calculated_at", "must not be zero")
	}

	return errs.ErrOrNil()
}
