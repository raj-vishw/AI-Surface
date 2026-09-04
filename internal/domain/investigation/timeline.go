package investigation

import (
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// EventType names one kind of thing that can appear on an investigation's
// timeline (phase9.md §10). Split into two families: the first block are
// materialized from real Phase 2-8 observation timestamps (never
// fabricated — phase9.md §11); the second block are this package's own
// audit trail of analyst/system actions taken against the investigation
// itself (phase9.md §61's audit-trail requirement is satisfied by these
// same rows — see the package doc comment on why a second, separate audit
// log table was not introduced).
type EventType string

// Recognized timeline event types.
const (
	// Observation-sourced (phase9.md §10's first list).
	EventAssetDiscovered    EventType = "asset_discovered"
	EventAssetChanged       EventType = "asset_changed"
	EventEndpointDiscovered EventType = "endpoint_discovered"
	EventEndpointChanged    EventType = "endpoint_changed"
	EventFindingCreated     EventType = "finding_created"
	EventFindingResolved    EventType = "finding_resolved"
	EventFindingReopened    EventType = "finding_reopened"
	EventTechnologyChanged  EventType = "technology_changed"
	EventServiceChanged     EventType = "service_changed"
	EventScanStarted        EventType = "scan_started"
	EventScanCompleted      EventType = "scan_completed"
	EventAnalystNote        EventType = "analyst_note"
	EventIncidentCreated    EventType = "incident_created"
	EventIncidentUpdated    EventType = "incident_updated"
	EventIncidentClosed     EventType = "incident_closed"

	// Investigation audit actions (phase9.md §61) — granular siblings of
	// the incident_* events above, covering every mutation §61 lists.
	EventInvestigationCreated  EventType = "investigation_created"
	EventSeverityChanged       EventType = "severity_changed"
	EventPriorityChanged       EventType = "priority_changed"
	EventAssignmentChanged     EventType = "assignment_changed"
	EventStatusChanged         EventType = "status_changed"
	EventFindingAttached       EventType = "finding_attached"
	EventEvidenceAttached      EventType = "evidence_attached"
	EventHypothesisCreated     EventType = "hypothesis_created"
	EventHypothesisUpdated     EventType = "hypothesis_updated"
	EventRelationshipCreated   EventType = "relationship_created"
	EventInvestigationReopened EventType = "investigation_reopened"
)

var validEventTypes = map[EventType]bool{
	EventAssetDiscovered: true, EventAssetChanged: true, EventEndpointDiscovered: true,
	EventEndpointChanged: true, EventFindingCreated: true, EventFindingResolved: true,
	EventFindingReopened: true, EventTechnologyChanged: true, EventServiceChanged: true,
	EventScanStarted: true, EventScanCompleted: true, EventAnalystNote: true,
	EventIncidentCreated: true, EventIncidentUpdated: true, EventIncidentClosed: true,
	EventInvestigationCreated: true, EventSeverityChanged: true, EventPriorityChanged: true,
	EventAssignmentChanged: true, EventStatusChanged: true, EventFindingAttached: true,
	EventEvidenceAttached: true, EventHypothesisCreated: true, EventHypothesisUpdated: true,
	EventRelationshipCreated: true, EventInvestigationReopened: true,
}

// Valid reports whether t is a recognized timeline event type.
func (t EventType) Valid() bool { return validEventTypes[t] }

// TimelineEvent is one entry on an investigation's chronological narrative
// (phase9.md §9/§10) — always scoped to exactly one investigation
// (materialized into it when relevant, e.g. when a finding is attached,
// its own finding_events history is projected in — see
// internal/service/investigation).
type TimelineEvent struct {
	ID              uuid.UUID
	TargetID        uuid.UUID
	InvestigationID uuid.UUID

	// Timestamp is when the underlying thing actually happened — a
	// finding's FirstSeen, an endpoint's FirstSeen, a note's CreatedAt —
	// never the time the row was materialized into this timeline
	// (phase9.md §11: "do not fabricate timestamps").
	Timestamp time.Time

	Type EventType

	SourceType EntityType
	SourceID   *uuid.UUID

	Title       string
	Description string
	Severity    string

	// Actor is who/what caused this event: an analyst's identifier, or
	// "system" for one materialized from an automated observation.
	Actor string

	Metadata map[string]any

	CreatedAt time.Time
}

// Validate checks that e is internally consistent.
func (e TimelineEvent) Validate() error {
	var errs validation.Errors

	if e.InvestigationID == uuid.Nil {
		errs = errs.Add("investigation_id", "must not be empty")
	}
	if e.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !e.Type.Valid() {
		errs = errs.Add("type", "must be a recognized event type")
	}
	if e.SourceType != "" && !e.SourceType.Valid() {
		errs = errs.Add("source_type", "must be a recognized entity type")
	}
	if e.Timestamp.IsZero() {
		errs = errs.Add("timestamp", "must not be zero")
	}
	if e.Title == "" {
		errs = errs.Add("title", "must not be empty")
	}

	return errs.ErrOrNil()
}
