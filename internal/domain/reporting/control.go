package reporting

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// ControlEvidence is a generic, framework-agnostic record linking a
// security control (identified only by an analyst-supplied ControlID
// string — phase14.md §50's own instruction: "do not hard-code a
// specific compliance framework unless one already exists in the
// project," and none does) to a piece of evidence already collected
// elsewhere in this platform.
//
// This is deliberately the only compliance-shaped structure Phase 14
// introduces — no framework mapping, no automatic control satisfaction,
// no compliance percentage. See docs/compliance/evidence.md.
type ControlEvidence struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	// ControlID is an analyst-supplied identifier for the control this
	// evidence relates to (e.g. "AC-2", "encryption-at-rest") — this
	// platform assigns it no meaning beyond a grouping key.
	ControlID string

	EvidenceType EvidenceItemType
	ReferenceID  uuid.UUID

	Description string

	// CollectedAt is when the underlying evidence was actually observed
	// (never fabricated — the same discipline every timeline/evidence
	// timestamp in this platform already follows).
	CollectedAt time.Time

	CreatedAt time.Time
}

// Validate checks that c is internally consistent.
func (c ControlEvidence) Validate() error {
	var errs validation.Errors
	if c.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if strings.TrimSpace(c.ControlID) == "" {
		errs = errs.Add("control_id", "must not be empty")
	}
	if !c.EvidenceType.Valid() {
		errs = errs.Add("evidence_type", "must be a recognized evidence item type")
	}
	if c.ReferenceID == uuid.Nil {
		errs = errs.Add("reference_id", "must not be empty")
	}
	if strings.TrimSpace(c.Description) == "" {
		errs = errs.Add("description", "must not be empty")
	}
	if c.CollectedAt.IsZero() {
		errs = errs.Add("collected_at", "must not be zero")
	}
	return errs.ErrOrNil()
}
