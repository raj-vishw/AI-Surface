package rule

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// AlertStatus tracks an Alert's analyst-facing lifecycle (phase11.md
// §21), distinct from the underlying DetectionMatch's own Status —
// resolving an alert never mutates or removes the match/evidence it
// references.
type AlertStatus string

// Recognized alert statuses.
const (
	AlertOpen          AlertStatus = "open"
	AlertAcknowledged  AlertStatus = "acknowledged"
	AlertInvestigating AlertStatus = "investigating"
	AlertResolved      AlertStatus = "resolved"
	AlertSuppressed    AlertStatus = "suppressed"
)

var validAlertStatuses = map[AlertStatus]bool{
	AlertOpen: true, AlertAcknowledged: true, AlertInvestigating: true, AlertResolved: true, AlertSuppressed: true,
}

// Valid reports whether s is a recognized alert status.
func (s AlertStatus) Valid() bool { return validAlertStatuses[s] }

// Alert is the analyst-facing notification for one DetectionMatch
// (phase11.md §20) — it references the match rather than duplicating
// its evidence (phase11.md §20's "do not duplicate all evidence").
type Alert struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	DetectionMatchID uuid.UUID

	Title       string
	Description string

	Severity   Severity
	Confidence Confidence

	Status AlertStatus

	// InvestigationID is set once this alert has been promoted into a
	// Phase 9 investigation (phase11.md §22) — nil until then.
	InvestigationID *uuid.UUID

	FirstObservedAt time.Time
	LastObservedAt  time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that a is internally consistent.
func (a Alert) Validate() error {
	var errs validation.Errors

	if a.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if a.DetectionMatchID == uuid.Nil {
		errs = errs.Add("detection_match_id", "must not be empty")
	}
	if strings.TrimSpace(a.Title) == "" {
		errs = errs.Add("title", "must not be empty")
	}
	if !a.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !a.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if !a.Status.Valid() {
		errs = errs.Add("status", "must be a recognized alert status")
	}

	return errs.ErrOrNil()
}
