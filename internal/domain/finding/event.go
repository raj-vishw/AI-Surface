package finding

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// EventType names one lifecycle transition recorded against a Finding
// (phase8.md §71) — an append-only audit trail distinct from Status
// itself: Status names "where the finding is now", Event rows name "every
// place it has ever been and when".
type EventType string

// Recognized finding lifecycle events.
const (
	EventOpened              EventType = "finding_opened"
	EventUpdated             EventType = "finding_updated"
	EventResolved            EventType = "finding_resolved"
	EventReopened            EventType = "finding_reopened"
	EventAccepted            EventType = "finding_accepted"
	EventMarkedFalsePositive EventType = "finding_marked_false_positive"
	EventSeverityOverridden  EventType = "finding_severity_overridden"
)

var validEventTypes = map[EventType]bool{
	EventOpened: true, EventUpdated: true, EventResolved: true, EventReopened: true,
	EventAccepted: true, EventMarkedFalsePositive: true, EventSeverityOverridden: true,
}

// Valid reports whether t is a recognized finding event type.
func (t EventType) Valid() bool { return validEventTypes[t] }

// Event is one immutable lifecycle transition for a Finding (phase8.md
// §71/§85). Never updated or deleted — a new transition is always a new
// row, exactly like Evidence.
type Event struct {
	ID         uuid.UUID
	FindingID  uuid.UUID
	ScanID     *uuid.UUID
	Type       EventType
	FromStatus Status
	ToStatus   Status
	Severity   Severity // the finding's severity at the time of this event
	Confidence Confidence
	Reason     string // required for EventAccepted/EventMarkedFalsePositive/EventSeverityOverridden
	DetectedAt time.Time
	CreatedAt  time.Time
}

// Validate checks that e is internally consistent.
func (e Event) Validate() error {
	var errs validation.Errors

	if e.FindingID == uuid.Nil {
		errs = errs.Add("finding_id", "must not be empty")
	}
	if !e.Type.Valid() {
		errs = errs.Add("type", "must be a recognized event type")
	}
	if e.ToStatus != "" && !e.ToStatus.Valid() {
		errs = errs.Add("to_status", "must be a recognized finding status")
	}
	if e.FromStatus != "" && !e.FromStatus.Valid() {
		errs = errs.Add("from_status", "must be a recognized finding status")
	}
	needsReason := e.Type == EventAccepted || e.Type == EventMarkedFalsePositive || e.Type == EventSeverityOverridden
	if needsReason && strings.TrimSpace(e.Reason) == "" {
		errs = errs.Add("reason", "must not be empty for this event type")
	}

	return errs.ErrOrNil()
}
