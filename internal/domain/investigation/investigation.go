// Package investigation defines the platform's analyst case-management
// model: an Investigation an analyst opens to understand a security
// situation, plus the Evidence/Timeline/Relationship/Hypothesis/Note
// records that build up around it (phase9.md §2-10). It mirrors
// internal/domain/finding's shape and independence discipline —
// no dependency on internal/domain/{asset,endpoint,finding}; every
// cross-entity reference is a bare uuid.UUID plus a string EntityType,
// exactly the "reference by id, not by type import" rule
// internal/domain/finding's own doc comment documents for itself.
//
// Design decision, documented once here rather than at every call site:
// phase9.md §3 asks for a distinct "Incident" entity whose fields
// (Severity/Confidence/Status/DetectedAt/FirstObservedAt/LastObservedAt)
// are almost a strict subset of Investigation's own (§2). Rather than
// introduce two nearly-identical tables/entities, an Incident here IS an
// Investigation — the same consolidation phase9.md §54 explicitly
// sanctions ("do not create duplicate endpoints if incidents are
// intentionally represented as investigations"). Investigation carries
// every field either section asked for. Likewise "ProjectID" is this
// platform's existing TargetID (see internal/domain/target) — the same
// mapping phase8.md's report already established for Finding, since no
// separate Project entity exists anywhere in this codebase.
package investigation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// Status tracks an Investigation's case-management lifecycle (phase9.md
// §2). Never deleted — a closed investigation's row, timeline, and
// evidence remain permanently queryable.
type Status string

// Recognized investigation statuses.
const (
	StatusNew           Status = "new"
	StatusOpen          Status = "open"
	StatusInvestigating Status = "investigating"
	StatusContained     Status = "contained"
	StatusResolved      Status = "resolved"
	StatusClosed        Status = "closed"
)

var validStatuses = map[Status]bool{
	StatusNew: true, StatusOpen: true, StatusInvestigating: true,
	StatusContained: true, StatusResolved: true, StatusClosed: true,
}

// Valid reports whether s is a recognized investigation status.
func (s Status) Valid() bool { return validStatuses[s] }

// Terminal reports whether s represents a closed investigation — the only
// state Reopen (see service layer) transitions away from.
func (s Status) Terminal() bool { return s == StatusClosed }

// Priority is analyst workflow metadata — "how soon should someone look
// at this" — deliberately a distinct axis from Severity ("how serious is
// the underlying situation") and Confidence ("how sure are we the
// interpretation is correct"); phase9.md §29 warns against confusing
// priority with severity, so the three are never collapsed into one field.
type Priority string

// Recognized priorities.
const (
	PriorityLow    Priority = "low"
	PriorityNormal Priority = "normal"
	PriorityHigh   Priority = "high"
	PriorityUrgent Priority = "urgent"
)

var validPriorities = map[Priority]bool{
	PriorityLow: true, PriorityNormal: true, PriorityHigh: true, PriorityUrgent: true,
}

// Valid reports whether p is a recognized priority.
func (p Priority) Valid() bool { return validPriorities[p] }

// Severity answers "how serious is the underlying situation" (phase9.md
// §6) — independently assigned or calculated, never a silent copy of the
// highest attached finding's severity without the calculation being
// documented (see internal/service/investigation's severity-suggestion
// logic, which is exactly such a documented rule, applied only as a
// starting suggestion an analyst can override).
type Severity string

// Recognized severities, informational to critical — the same five-value
// vocabulary internal/domain/finding.Severity uses, kept as an
// independent copy for this package's zero-cross-domain-dependency
// discipline.
const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInformational: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Valid reports whether s is a recognized severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Rank returns s's ordinal position, for sorting/threshold comparisons.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// Confidence answers "how confident are we that this investigation's
// interpretation is correct" (phase9.md §5) — never conflated with a
// finding's own severity or with a correlation score's numeric
// confidence (see internal/investigation.Confidence, an independent
// engine-side copy for the identical reason).
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceVeryLow  Confidence = "very_low"
	ConfidenceLow      Confidence = "low"
	ConfidenceMedium   Confidence = "medium"
	ConfidenceHigh     Confidence = "high"
	ConfidenceVeryHigh Confidence = "very_high"
)

var validConfidences = map[Confidence]bool{
	ConfidenceVeryLow: true, ConfidenceLow: true, ConfidenceMedium: true,
	ConfidenceHigh: true, ConfidenceVeryHigh: true,
}

// Valid reports whether c is a recognized confidence level. Empty is also
// valid — a brand-new investigation may not have an assigned confidence
// yet.
func (c Confidence) Valid() bool { return c == "" || validConfidences[c] }

// Investigation is one analyst case (phase9.md §2/§3 combined — see the
// package doc comment for why). It is never automatically merged or
// deduplicated: its ID is a fresh uuid.UUID assigned at creation, not a
// derived identity key like Finding's (phase9.md §7 — "investigations are
// analyst-controlled entities and should not unexpectedly merge").
type Investigation struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	Title       string
	Description string

	Status     Status
	Priority   Priority
	Severity   Severity
	Confidence Confidence

	CreatedBy  string
	AssignedTo string

	// DetectedAt/FirstObservedAt/LastObservedAt are the incident-facing
	// timestamps phase9.md §3 asks for — set from real evidence (the
	// earliest/latest FirstSeen/LastSeen of whatever is attached), never
	// fabricated; nil until at least one piece of evidence is attached.
	DetectedAt      *time.Time
	FirstObservedAt *time.Time
	LastObservedAt  *time.Time

	// Version supports optimistic concurrency control (phase9.md §74):
	// Update fails with a conflict if the caller's expected version no
	// longer matches the stored one, rather than silently clobbering a
	// concurrent analyst's edit.
	Version int

	CreatedAt time.Time
	UpdatedAt time.Time
	ClosedAt  *time.Time
}

// Validate checks that inv is internally consistent.
func (inv Investigation) Validate() error {
	var errs validation.Errors

	if inv.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if strings.TrimSpace(inv.Title) == "" {
		errs = errs.Add("title", "must not be empty")
	}
	if !inv.Status.Valid() {
		errs = errs.Add("status", "must be a recognized investigation status")
	}
	if inv.Priority != "" && !inv.Priority.Valid() {
		errs = errs.Add("priority", "must be a recognized priority")
	}
	if inv.Severity != "" && !inv.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !inv.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if strings.TrimSpace(inv.CreatedBy) == "" {
		errs = errs.Add("created_by", "must not be empty")
	}

	return errs.ErrOrNil()
}

// EntityType names what kind of thing a cross-reference (Relationship
// source/target, EvidenceRef source, TimelineEvent source) points at —
// shared across relationship.go/evidence.go/timeline.go.
type EntityType string

// Recognized entity types.
const (
	EntityFinding       EntityType = "finding"
	EntityAsset         EntityType = "asset"
	EntityEndpoint      EntityType = "endpoint"
	EntityTechnology    EntityType = "technology"
	EntityScan          EntityType = "scan"
	EntityTimelineEvent EntityType = "timeline_event"
	EntityInvestigation EntityType = "investigation"
)

var validEntityTypes = map[EntityType]bool{
	EntityFinding: true, EntityAsset: true, EntityEndpoint: true, EntityTechnology: true,
	EntityScan: true, EntityTimelineEvent: true, EntityInvestigation: true,
}

// Valid reports whether t is a recognized entity type.
func (t EntityType) Valid() bool { return validEntityTypes[t] }
