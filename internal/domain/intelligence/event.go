package intelligence

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// EventType names what kind of change an EnrichmentEvent records
// (phase10.md §48/§49/§50).
type EventType string

// Recognized enrichment event types.
const (
	EventVerdictChanged            EventType = "verdict_changed"
	EventConfidenceChanged         EventType = "confidence_changed"
	EventNewMaliciousReputation    EventType = "new_malicious_reputation"
	EventVulnerabilityMatchCreated EventType = "vulnerability_match_created"
	EventVulnerabilitySeverityUp   EventType = "vulnerability_severity_increased"
	EventRiskScoreIncreased        EventType = "risk_score_increased"
	EventIntelligenceConflict      EventType = "intelligence_conflict"
	EventProviderEnabled           EventType = "provider_enabled"
	EventProviderDisabled          EventType = "provider_disabled"
)

var validEventTypes = map[EventType]bool{
	EventVerdictChanged: true, EventConfidenceChanged: true, EventNewMaliciousReputation: true,
	EventVulnerabilityMatchCreated: true, EventVulnerabilitySeverityUp: true,
	EventRiskScoreIncreased: true, EventIntelligenceConflict: true,
	EventProviderEnabled: true, EventProviderDisabled: true,
}

// Valid reports whether t is a recognized event type.
func (t EventType) Valid() bool { return validEventTypes[t] }

// EnrichmentEvent records one detected change worth surfacing (phase10.md
// §48/§51) — "new finding" followed by "vulnerability match created"
// produces one of these. This platform stops at producing the event; it
// does not implement delivery/notification (phase10.md §49).
type EnrichmentEvent struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	// IndicatorType/IndicatorValue identify the subject when the event is
	// indicator-scoped (verdict/confidence changes); empty for
	// entity-scoped events (vulnerability/risk changes), which instead
	// use SourceID to name the affected row.
	IndicatorType  IndicatorType
	IndicatorValue string

	EventType EventType

	// Source is the provider id (or "risk_engine" / "vulnerability_
	// matcher" for internally-generated events) that produced this
	// event.
	Source   string
	SourceID string

	Timestamp time.Time

	PreviousValue string
	NewValue      string
	Confidence    Confidence

	CreatedAt time.Time
}

// Validate checks that e is internally consistent.
func (e EnrichmentEvent) Validate() error {
	var errs validation.Errors

	if e.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !e.EventType.Valid() {
		errs = errs.Add("event_type", "must be a recognized event type")
	}
	if strings.TrimSpace(e.Source) == "" {
		errs = errs.Add("source", "must not be empty")
	}
	if e.Timestamp.IsZero() {
		errs = errs.Add("timestamp", "must not be zero")
	}

	return errs.ErrOrNil()
}
