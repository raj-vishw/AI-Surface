package rule

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// MatchStatus tracks a DetectionMatch's lifecycle (phase11.md §16).
type MatchStatus string

// Recognized match statuses.
const (
	MatchOpen         MatchStatus = "open"
	MatchAcknowledged MatchStatus = "acknowledged"
	MatchResolved     MatchStatus = "resolved"
	MatchSuppressed   MatchStatus = "suppressed"
)

var validMatchStatuses = map[MatchStatus]bool{
	MatchOpen: true, MatchAcknowledged: true, MatchResolved: true, MatchSuppressed: true,
}

// Valid reports whether s is a recognized match status.
func (s MatchStatus) Valid() bool { return validMatchStatuses[s] }

// DetectionMatch is one rule version's confirmed match against a group
// of normalized observations (phase11.md §16) — always traceable to
// exactly one (RuleID, RuleVersion) pair (phase11.md §4's "a detection
// result must always be traceable to rule ID and rule version").
// Re-observing the identical underlying pattern within the same
// deduplication window widens LastObservedAt on the existing row rather
// than creating a duplicate — see Fingerprint and internal/ruleengine.
// ComputeFingerprint.
type DetectionMatch struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	RuleID      uuid.UUID
	RuleVersion int

	// Fingerprint is the deduplication key (phase11.md §33): rule ID +
	// rule version + relevant group keys + a normalized time window —
	// never an unstable value (a random UUID, a raw timestamp) that
	// would defeat deduplication.
	Fingerprint string

	FirstObservedAt time.Time
	LastObservedAt  time.Time

	Severity   Severity
	Confidence Confidence

	Status MatchStatus

	// Explanation is a human-readable statement of why this rule fired —
	// never merely "rule matched" (phase11.md §17/§18); see
	// internal/ruleengine.Explain.
	Explanation string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that m is internally consistent.
func (m DetectionMatch) Validate() error {
	var errs validation.Errors

	if m.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if m.RuleID == uuid.Nil {
		errs = errs.Add("rule_id", "must not be empty")
	}
	if m.RuleVersion < 1 {
		errs = errs.Add("rule_version", "must be at least 1")
	}
	if strings.TrimSpace(m.Fingerprint) == "" {
		errs = errs.Add("fingerprint", "must not be empty")
	}
	if m.FirstObservedAt.IsZero() {
		errs = errs.Add("first_observed_at", "must not be zero")
	}
	if !m.Severity.Valid() {
		errs = errs.Add("severity", "must be a recognized severity")
	}
	if !m.Confidence.Valid() {
		errs = errs.Add("confidence", "must be a recognized confidence level")
	}
	if !m.Status.Valid() {
		errs = errs.Add("status", "must be a recognized match status")
	}
	if strings.TrimSpace(m.Explanation) == "" {
		errs = errs.Add("explanation", "must not be empty — a match is never persisted without an explanation")
	}

	return errs.ErrOrNil()
}
