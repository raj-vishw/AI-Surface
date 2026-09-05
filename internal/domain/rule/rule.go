// Package rule defines the platform's canonical detection-rule model:
// user-authored, versioned rules that evaluate normalized observations
// from this platform's own already-persisted data (findings, assets,
// endpoints, technology fingerprints, threat intelligence — see
// internal/ruleengine's package doc comment for why there is no separate
// raw-log/event-ingestion pipeline here), plus the matches, evidence,
// alerts, and suppressions those rules produce.
//
// It mirrors internal/domain/investigation and internal/domain/
// intelligence's shape deliberately — a normalized, evidence-backed
// record type plus small satellite record types — rather than inventing
// a parallel modeling style. This package holds only the *persisted*
// representation; the engine that parses/validates/compiles/evaluates a
// rule definition lives in internal/ruleengine and has no dependency on
// this package (mirroring internal/detection's independence from
// internal/domain/finding); internal/service/rule is the bridge.
//
// This package never imports internal/domain/asset, internal/domain/
// finding, internal/domain/investigation, or internal/domain/
// intelligence — cross-entity references (AssetID, an underlying
// finding/asset/endpoint row referenced by evidence) are always a bare
// uuid.UUID, the same discipline phase8.md/phase9.md/phase10.md
// established.
package rule

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// Status tracks a Rule's lifecycle (phase11.md §3/§30). A rule is never
// hard-deleted — a retired rule moves to deprecated, preserving every
// historical match's traceability to it.
type Status string

// Recognized rule statuses.
const (
	StatusDraft      Status = "draft"
	StatusEnabled    Status = "enabled"
	StatusDisabled   Status = "disabled"
	StatusDeprecated Status = "deprecated"
)

var validStatuses = map[Status]bool{
	StatusDraft: true, StatusEnabled: true, StatusDisabled: true, StatusDeprecated: true,
}

// Valid reports whether s is a recognized rule status.
func (s Status) Valid() bool { return validStatuses[s] }

// Active reports whether a rule in this status is eligible to produce
// new matches (phase11.md §31) — enabled only; draft/disabled/
// deprecated never generate a new match, though their history remains
// visible.
func (s Status) Active() bool { return s == StatusEnabled }

// Type names which of the four supported rule languages a rule uses
// (phase11.md §6) — deliberately a small, closed set, never a general
// programming language.
type Type string

// Recognized rule types.
const (
	TypeFieldMatch  Type = "field_match"
	TypeThreshold   Type = "threshold"
	TypeSequence    Type = "sequence"
	TypeAggregation Type = "aggregation"
)

var validTypes = map[Type]bool{
	TypeFieldMatch: true, TypeThreshold: true, TypeSequence: true, TypeAggregation: true,
}

// Valid reports whether t is a recognized rule type.
func (t Type) Valid() bool { return validTypes[t] }

// Severity mirrors internal/domain/finding.Severity's vocabulary — an
// independent copy, per this package's "no domain package imports
// another domain package" discipline (see package doc comment).
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

// Rank returns s's ordinal position, -1 if unrecognized.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// Confidence answers "how confident are we that this rule's match
// reflects a real pattern, not noise?" — kept separate from Severity
// (phase11.md §27: "how serious" vs "how sure" are never mixed), and an
// independent copy of internal/domain/finding.Confidence's level
// vocabulary (this package has no dependency on that package).
type Confidence string

// Recognized confidence levels, very_low to very_high.
const (
	ConfidenceVeryLow  Confidence = "very_low"
	ConfidenceLow      Confidence = "low"
	ConfidenceMedium   Confidence = "medium"
	ConfidenceHigh     Confidence = "high"
	ConfidenceVeryHigh Confidence = "very_high"
)

var confidenceRank = map[Confidence]int{
	ConfidenceVeryLow: 0, ConfidenceLow: 1, ConfidenceMedium: 2, ConfidenceHigh: 3, ConfidenceVeryHigh: 4,
}

// Valid reports whether c is a recognized confidence level.
func (c Confidence) Valid() bool { _, ok := confidenceRank[c]; return ok }

// Rank returns c's ordinal position, -1 if unrecognized.
func (c Confidence) Rank() int {
	if r, ok := confidenceRank[c]; ok {
		return r
	}
	return -1
}

// Rule is one detection rule's identity and current metadata
// (phase11.md §3) — the versioned Definition itself lives in
// RuleVersion (see version.go); Rule never carries rule logic directly,
// so editing a rule's language/logic always goes through the versioning
// path (phase11.md §4/§5).
type Rule struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	Name        string
	Description string

	Status   Status
	RuleType Type

	Severity   Severity
	Confidence Confidence

	// Category/Tags/References/DocumentationURL are optional metadata
	// (phase11.md §28/§29) — DocumentationURL is never required
	// (phase11.md §29).
	Category         string
	Tags             []string
	References       []string
	DocumentationURL string

	CreatedBy string
	UpdatedBy string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that r is internally consistent.
func (r Rule) Validate() error {
	var errs validation.Errors

	if r.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if strings.TrimSpace(r.Name) == "" {
		errs = errs.Add("name", "must not be empty")
	}
	if !r.Status.Valid() {
		errs = errs.Add("status", "must be a recognized rule status")
	}
	if !r.RuleType.Valid() {
		errs = errs.Add("rule_type", "must be a recognized rule type")
	}
	if !r.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !r.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if strings.TrimSpace(r.CreatedBy) == "" {
		errs = errs.Add("created_by", "must not be empty")
	}

	return errs.ErrOrNil()
}
