package investigation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// HypothesisStatus tracks an analyst hypothesis's own lifecycle,
// independent of the parent Investigation's Status (phase9.md §24).
type HypothesisStatus string

// Recognized hypothesis statuses.
const (
	HypothesisProposed      HypothesisStatus = "proposed"
	HypothesisInvestigating HypothesisStatus = "investigating"
	HypothesisSupported     HypothesisStatus = "supported"
	HypothesisUnsupported   HypothesisStatus = "unsupported"
	HypothesisConfirmed     HypothesisStatus = "confirmed"
	HypothesisRejected      HypothesisStatus = "rejected"
)

var validHypothesisStatuses = map[HypothesisStatus]bool{
	HypothesisProposed: true, HypothesisInvestigating: true, HypothesisSupported: true,
	HypothesisUnsupported: true, HypothesisConfirmed: true, HypothesisRejected: true,
}

// Valid reports whether s is a recognized hypothesis status.
func (s HypothesisStatus) Valid() bool { return validHypothesisStatuses[s] }

// Hypothesis is an analyst's stated, falsifiable theory about what's
// going on (phase9.md §24) — never represented as fact; see
// HypothesisEvidence, which is what a hypothesis actually rests on.
type Hypothesis struct {
	ID              uuid.UUID
	InvestigationID uuid.UUID

	Title       string
	Description string

	Status     HypothesisStatus
	Confidence Confidence

	CreatedBy string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that h is internally consistent.
func (h Hypothesis) Validate() error {
	var errs validation.Errors

	if h.InvestigationID == uuid.Nil {
		errs = errs.Add("investigation_id", "must not be empty")
	}
	if strings.TrimSpace(h.Title) == "" {
		errs = errs.Add("title", "must not be empty")
	}
	if !h.Status.Valid() {
		errs = errs.Add("status", "must be a recognized hypothesis status")
	}
	if !h.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if strings.TrimSpace(h.CreatedBy) == "" {
		errs = errs.Add("created_by", "must not be empty")
	}

	return errs.ErrOrNil()
}

// HypothesisEvidence is one explicit, cited piece of support for a
// Hypothesis (phase9.md §25) — "endpoint first seen at 10:05", never bare
// speculation. Distinct from EvidenceRef (which attaches evidence to the
// investigation as a whole) — a HypothesisEvidence row says *why this
// specific theory* is or isn't supported.
type HypothesisEvidence struct {
	ID           uuid.UUID
	HypothesisID uuid.UUID

	SourceType  EntityType
	SourceID    uuid.UUID
	Description string
	ObservedAt  time.Time

	CreatedAt time.Time
}

// Validate checks that e is internally consistent.
func (e HypothesisEvidence) Validate() error {
	var errs validation.Errors

	if e.HypothesisID == uuid.Nil {
		errs = errs.Add("hypothesis_id", "must not be empty")
	}
	if !e.SourceType.Valid() {
		errs = errs.Add("source_type", "must be a recognized entity type")
	}
	if e.SourceID == uuid.Nil {
		errs = errs.Add("source_id", "must not be empty")
	}
	if strings.TrimSpace(e.Description) == "" {
		errs = errs.Add("description", "must not be empty")
	}

	return errs.ErrOrNil()
}
