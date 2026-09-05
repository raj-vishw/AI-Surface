package rule

import (
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// SourceType names which already-persisted entity kind an underlying
// event came from (phase11.md §94/§9) — this platform has no separate
// raw-log/event-ingestion pipeline (see internal/ruleengine's package
// doc comment), so "the normalized event" a rule evaluates is always a
// projection of one of these already-normalized rows.
type SourceType string

// Recognized event source types.
const (
	SourceFinding             SourceType = "finding"
	SourceAssetObservation    SourceType = "asset_observation"
	SourceEndpointObservation SourceType = "endpoint_observation"
	SourceFingerprintChange   SourceType = "fingerprint_change"
	SourceIntelligenceRecord  SourceType = "intelligence_record"
)

var validSourceTypes = map[SourceType]bool{
	SourceFinding: true, SourceAssetObservation: true, SourceEndpointObservation: true,
	SourceFingerprintChange: true, SourceIntelligenceRecord: true,
}

// Valid reports whether t is a recognized source type.
func (t SourceType) Valid() bool { return validSourceTypes[t] }

// EvidenceRole names why one underlying event was attached to a match
// (phase11.md §63).
type EvidenceRole string

// Recognized evidence roles.
const (
	RoleTrigger      EvidenceRole = "trigger"
	RoleSupporting   EvidenceRole = "supporting"
	RoleSequenceStep EvidenceRole = "sequence_step"
)

var validRoles = map[EvidenceRole]bool{
	RoleTrigger: true, RoleSupporting: true, RoleSequenceStep: true,
}

// Valid reports whether r is a recognized evidence role.
func (r EvidenceRole) Valid() bool { return validRoles[r] }

// MatchEvidence is one underlying observation that contributed to a
// DetectionMatch — a reference, never a copy (phase11.md §17: "the
// match must explain which events caused the detection", never only
// "rule matched"). SourceID points at the underlying finding/asset/
// endpoint/fingerprint/intelligence-record row; ObservedAt is that row's
// own real timestamp, never fabricated.
type MatchEvidence struct {
	ID               uuid.UUID
	DetectionMatchID uuid.UUID

	SourceType SourceType
	SourceID   uuid.UUID
	Role       EvidenceRole

	ObservedAt time.Time
	CreatedAt  time.Time
}

// Validate checks that e is internally consistent.
func (e MatchEvidence) Validate() error {
	var errs validation.Errors

	if e.DetectionMatchID == uuid.Nil {
		errs = errs.Add("detection_match_id", "must not be empty")
	}
	if !e.SourceType.Valid() {
		errs = errs.Add("source_type", "must be a recognized source type")
	}
	if e.SourceID == uuid.Nil {
		errs = errs.Add("source_id", "must not be empty")
	}
	if !e.Role.Valid() {
		errs = errs.Add("role", "must be a recognized evidence role")
	}
	if e.ObservedAt.IsZero() {
		errs = errs.Add("observed_at", "must not be zero")
	}

	return errs.ErrOrNil()
}
