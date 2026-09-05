// Package ruleengine implements Phase 11's detection rule engine: a
// self-contained, versioned, deterministic evaluator of user-authored
// rules against normalized observations. Mirroring internal/detection
// and internal/investigation's split (phase8.md §1/phase9.md §1), this
// package has no dependency on internal/domain/rule or any database/
// repository package — Engine.Evaluate takes an in-memory Definition and
// []Event and returns in-memory Match values; internal/service/rule is
// the bridge that resolves configuration, assembles Events from
// already-persisted data, calls Engine.Evaluate, and persists the
// result.
//
// IMPORTANT — what "event" means on this platform: phase11.md assumes a
// raw-log-ingestion pipeline ("logs -> normalization -> events") that
// this platform does not have and Phase 11 does not add (per explicit
// direction: reuse existing architecture, do not rebuild it). Instead,
// an Event here is a normalized *projection* of a row this platform
// already persisted and already normalized in an earlier phase — a
// Phase 8 Finding, a Phase 2 Asset observation, a Phase 7 Endpoint
// observation, a Phase 6 Fingerprint change, or a Phase 10 Intelligence
// record. internal/service/rule's event-assembly code builds Events from
// these rows on demand; no new event-log table is introduced (that would
// duplicate data this platform already stores). This is the same
// discipline internal/detection's Input already applies to its own
// inputs (AssetObservation/EndpointObservation/TLSObservation/
// ServiceObservation/FingerprintObservation), generalized here into a
// single flat, rule-addressable shape.
package ruleengine

import (
	"time"

	"github.com/google/uuid"
)

// EventType names which already-persisted entity kind an Event was
// projected from — an independent copy of
// internal/domain/rule.SourceType's vocabulary (this package has no
// dependency on that package; see package doc comment).
type EventType string

// Recognized event types.
const (
	EventFinding             EventType = "finding"
	EventAssetObservation    EventType = "asset_observation"
	EventEndpointObservation EventType = "endpoint_observation"
	EventFingerprintChange   EventType = "fingerprint_change"
	EventIntelligenceRecord  EventType = "intelligence_record"
)

var validEventTypes = map[EventType]bool{
	EventFinding: true, EventAssetObservation: true, EventEndpointObservation: true,
	EventFingerprintChange: true, EventIntelligenceRecord: true,
}

// Valid reports whether t is a recognized event type.
func (t EventType) Valid() bool { return validEventTypes[t] }

// Event is one normalized observation a rule may evaluate — a
// projection of an already-persisted row, never a copy stored
// separately (see package doc comment). SourceID identifies exactly
// which underlying row this Event came from, so a Match's evidence can
// always reference it directly.
type Event struct {
	Type     EventType
	SourceID uuid.UUID
	TargetID uuid.UUID
	// AssetID is uuid.Nil for event types not tied to one specific asset
	// (e.g. a target-wide intelligence record).
	AssetID uuid.UUID
	// Timestamp is the underlying row's own real timestamp (a finding's
	// FirstSeen, an asset's LastSeen, an intelligence record's
	// RetrievedAt, ...) — never fabricated, and never the moment this
	// Event struct happened to be constructed (phase11.md §45).
	Timestamp time.Time
	// Fields carries the normalized, rule-addressable field values —
	// see FieldSchema for the closed set of fields each EventType
	// supports and their types.
	Fields map[string]any
}
