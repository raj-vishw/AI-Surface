package investigation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// RelationType names how a piece of attached evidence relates to an
// investigation's working theory (phase9.md §4) — deliberately never a
// bare boolean "related: true"; only meaningful for EntityFinding
// references (empty for asset/endpoint/scan/timeline_event references,
// which are attached as supporting context, not as a claim about the
// investigation's central hypothesis).
type RelationType string

// Recognized relation types.
const (
	RelationRelated    RelationType = "related"
	RelationCorrelated RelationType = "correlated"
	RelationSuspected  RelationType = "suspected"
	RelationConfirmed  RelationType = "confirmed"
)

var validRelationTypes = map[RelationType]bool{
	RelationRelated: true, RelationCorrelated: true, RelationSuspected: true, RelationConfirmed: true,
}

// Valid reports whether r is a recognized relation type. Empty is valid —
// only finding references populate it.
func (r RelationType) Valid() bool { return r == "" || validRelationTypes[r] }

// EvidenceRef is one reference an investigation holds to something else
// already persisted elsewhere in the platform — a finding, an asset, an
// endpoint, a scan, or another investigation's timeline event (phase9.md
// §32/§33). It is a reference, never a copy: EvidenceRef stores only the
// provenance (source_type, source_id, when it was actually observed, when
// and by whom it was attached — phase9.md §34's "evidence chain"), so
// when the underlying finding/asset/endpoint later changes, the
// investigation's evidence list reflects that change automatically on
// the next read rather than holding a stale snapshot that silently
// diverges from reality.
type EvidenceRef struct {
	ID              uuid.UUID
	InvestigationID uuid.UUID

	SourceType EntityType
	SourceID   uuid.UUID

	// RelationType is set only when SourceType is EntityFinding
	// (phase9.md §4) — see RelationType's doc comment.
	RelationType RelationType

	// ObservedAt is when the underlying evidence was actually observed
	// (a finding's FirstSeen, an asset's FirstSeen, ...) — never
	// fabricated; AddedAt is when an analyst (or the correlation engine)
	// attached it to this investigation, which is typically much later.
	ObservedAt time.Time
	AddedAt    time.Time
	AddedBy    string

	CreatedAt time.Time
}

// Validate checks that e is internally consistent.
func (e EvidenceRef) Validate() error {
	var errs validation.Errors

	if e.InvestigationID == uuid.Nil {
		errs = errs.Add("investigation_id", "must not be empty")
	}
	if !e.SourceType.Valid() {
		errs = errs.Add("source_type", "must be a recognized entity type")
	}
	if e.SourceID == uuid.Nil {
		errs = errs.Add("source_id", "must not be empty")
	}
	if !e.RelationType.Valid() {
		errs = errs.Add("relation_type", "must be a recognized relation type")
	}
	if e.SourceType != EntityFinding && e.RelationType != "" {
		errs = errs.Add("relation_type", "must be empty unless source_type is finding")
	}
	if strings.TrimSpace(e.AddedBy) == "" {
		errs = errs.Add("added_by", "must not be empty")
	}

	return errs.ErrOrNil()
}
