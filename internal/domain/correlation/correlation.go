// Package correlation defines Phase 12's persisted correlation model: a
// Correlation groups multiple already-persisted security observations
// (Phase 8 findings, Phase 11 detection matches/alerts, Phase 10
// intelligence records, Phase 2 assets, Phase 9 relationships) that share
// meaningful, evidence-backed relationships — surfaced as a
// CorrelationGraph of Node/Edge values, optionally
// summarized as an AttackChain (phase12.md §4/§40).
//
// It mirrors internal/domain/rule's shape and independence discipline
// exactly: this package holds only the *persisted* representation, never
// imports another internal/domain/* package (cross-entity references are
// always a bare uuid.UUID plus a named SourceType/NodeType), and the
// engine that produces correlation results from in-memory evidence —
// strategy evaluation, graph assembly, scoring, explanation — lives in
// internal/correlation and has no dependency on this package;
// internal/service/correlation is the bridge (the same split phase8.md
// §1/phase9.md §1/phase11.md §1 each established for their own engine).
//
// A Correlation never claims a "confirmed attack" on its own — Status
// starts at open/investigating and only ever reaches confirmed through an
// explicit analyst action (Service.Confirm), never automatically
// (phase12.md §46/§47).
package correlation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Status tracks a Correlation's analyst-workflow lifecycle (phase12.md
// §4). A system-generated Correlation always starts Open — Confirmed and
// Dismissed are only ever reached through an explicit analyst action (see
// internal/service/correlation's Confirm/Dismiss), never inferred by the
// engine itself (phase12.md §46).
type Status string

// Recognized correlation statuses.
const (
	StatusOpen          Status = "open"
	StatusInvestigating Status = "investigating"
	StatusConfirmed     Status = "confirmed"
	StatusResolved      Status = "resolved"
	StatusDismissed     Status = "dismissed"
)

var validStatuses = map[Status]bool{
	StatusOpen: true, StatusInvestigating: true, StatusConfirmed: true,
	StatusResolved: true, StatusDismissed: true,
}

// Valid reports whether s is a recognized correlation status.
func (s Status) Valid() bool { return validStatuses[s] }

// Severity mirrors internal/domain/finding.Severity's five-level
// vocabulary — an independent copy for this package's zero-cross-domain-
// dependency discipline (the same split every prior phase's domain
// package keeps).
type Severity string

// Recognized severities, informational to critical.
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

// Confidence is a three-level (not five-level) vocabulary, deliberately —
// phase12.md §9/§32 both spec confidence as low/medium/high for edges and
// for a correlation as a whole ("Score: 78, Confidence: Medium"), a
// coarser question ("how sure are we this grouping is meaningful") than
// internal/domain/investigation.Confidence's five-level "how confident is
// this investigation's interpretation" or internal/domain/rule.
// Confidence's finding-derived scale. Kept as an independent copy rather
// than reusing either.
type Confidence string

// Recognized confidence levels.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

var validConfidences = map[Confidence]bool{ConfidenceLow: true, ConfidenceMedium: true, ConfidenceHigh: true}

// Valid reports whether c is a recognized confidence level.
func (c Confidence) Valid() bool { return validConfidences[c] }

// ConfidenceForScore buckets a 0-100 correlation Score into a Confidence
// level — documented once here rather than re-derived ad hoc (phase12.md
// §32's "calculate confidence separately from score" still requires one
// documented mapping from score to level, the same discipline
// internal/investigation.ConfidenceForScore established for Phase 9).
func ConfidenceForScore(score int) Confidence {
	switch {
	case score >= 75:
		return ConfidenceHigh
	case score >= 45:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// ModelVersion is the correlation result-shape version stamped on every
// Correlation this engine revision produces (phase12.md §109) — bumped
// only when the scoring/graph-shape algorithm materially changes, so a
// historical Correlation remains interpretable even after the engine
// evolves. Never rewritten on an existing row (phase12.md §108: source
// data changing produces a new evaluation result, not a silent rewrite of
// history).
const ModelVersion = "v1"

// Correlation is a system-suggested (or analyst-confirmed) grouping of
// related security observations (phase12.md §4). It is explicitly never
// presented as "confirmed attack" language on its own — see Status and
// Title/Description, which must describe what was observed, not assert an
// unproven conclusion (phase12.md §3/§46).
type Correlation struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	Title       string
	Description string

	Status Status

	Severity   Severity
	Confidence Confidence
	// Score is a 0-100 value reflecting evidence strength/temporal
	// coherence/entity overlap/detection confidence/intelligence context
	// (phase12.md §31) — never described as a probability of attack (see
	// internal/correlation.Score's doc comment for the exact formula).
	Score int

	// Fingerprint is the deduplication key (phase12.md §27): re-evaluating
	// the same evidence set widens LastObservedAt on the existing row
	// rather than creating a duplicate (phase12.md §28) — see
	// internal/correlation.ComputeFingerprint.
	Fingerprint string
	// ModelVersion records which engine revision produced this row
	// (phase12.md §109) — always internal/correlation's ModelVersion
	// constant at write time, but the persisted value never changes
	// afterward even if the engine is later upgraded.
	ModelVersion string

	FirstObservedAt time.Time
	LastObservedAt  time.Time

	// InvestigationID is set once this correlation has been attached to a
	// Phase 9 investigation (phase12.md §35) — nil until then.
	InvestigationID *uuid.UUID

	// ConfirmedBy/ConfirmedAt/ConfirmationNotes are populated only by an
	// explicit analyst action (phase12.md §47) — never inferred.
	ConfirmedBy       string
	ConfirmedAt       *time.Time
	ConfirmationNotes string

	// DismissedBy/DismissedAt/DismissalReason are populated only by an
	// explicit analyst action; Reason is required (phase12.md §48).
	DismissedBy     string
	DismissedAt     *time.Time
	DismissalReason string

	// MergedIntoID is set on a correlation that was absorbed by another
	// via Service.Merge (phase12.md §29) — the row itself is preserved,
	// never deleted, so its original ID and evidence chain remain
	// queryable (phase12.md §29's "preserve original correlation IDs").
	MergedIntoID *uuid.UUID
	// MergedFromIDs lists every correlation ID this row absorbed, in the
	// order they were merged — populated only on the surviving
	// correlation.
	MergedFromIDs []uuid.UUID
	// SplitFromID is set on a correlation created by Service.Split
	// (phase12.md §30) — points at the original correlation it was split
	// out of, which is itself preserved unmodified except for having its
	// own evidence set narrowed to what remains assigned to it.
	SplitFromID *uuid.UUID

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that c is internally consistent.
func (c Correlation) Validate() error {
	var errs validation.Errors

	if c.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if strings.TrimSpace(c.Title) == "" {
		errs = errs.Add("title", "must not be empty")
	}
	if !c.Status.Valid() {
		errs = errs.Add("status", "must be a recognized correlation status")
	}
	if !c.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !c.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if c.Score < 0 || c.Score > 100 {
		errs = errs.Add("score", "must be between 0 and 100")
	}
	if strings.TrimSpace(c.Fingerprint) == "" {
		errs = errs.Add("fingerprint", "must not be empty")
	}
	if c.FirstObservedAt.IsZero() {
		errs = errs.Add("first_observed_at", "must not be zero")
	}
	if c.Status == StatusConfirmed && strings.TrimSpace(c.ConfirmedBy) == "" {
		errs = errs.Add("confirmed_by", "must not be empty when status is confirmed")
	}
	if c.Status == StatusDismissed && strings.TrimSpace(c.DismissalReason) == "" {
		errs = errs.Add("dismissal_reason", "must not be empty when status is dismissed")
	}

	return errs.ErrOrNil()
}
