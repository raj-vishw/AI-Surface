package rule

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// SuppressionScope names what a Suppression applies to (phase11.md
// §35/§36) — an entire rule (no new matches from it at all), one
// specific match, or one specific alert.
type SuppressionScope string

// Recognized suppression scopes.
const (
	ScopeRule  SuppressionScope = "rule"
	ScopeMatch SuppressionScope = "match"
	ScopeAlert SuppressionScope = "alert"
)

var validScopes = map[SuppressionScope]bool{
	ScopeRule: true, ScopeMatch: true, ScopeAlert: true,
}

// Valid reports whether s is a recognized suppression scope.
func (s SuppressionScope) Valid() bool { return validScopes[s] }

// Suppression records an analyst's (or the deduplication policy's)
// decision to suppress future noise from a rule/match/alert
// (phase11.md §35/§36) — it never deletes the underlying evidence or
// events (phase11.md §35: "suppression must not delete evidence"; §36:
// "do not permanently hide the underlying events"). A Suppression row is
// never deleted either — RemovedAt/RemovedBy record an explicit removal
// so the full suppression history stays auditable (phase11.md §37).
type Suppression struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	Scope   SuppressionScope
	ScopeID uuid.UUID

	// Reason is always required (phase11.md §36) — e.g. "expected
	// maintenance", "known scanner", "false positive", "approved
	// activity".
	Reason    string
	CreatedBy string
	CreatedAt time.Time
	// ExpiresAt is nil for an indefinite suppression, or a future time
	// after which the suppression is no longer considered active
	// (phase11.md §34's "suppress identical alerts for 30 minutes").
	ExpiresAt *time.Time

	RemovedAt *time.Time
	RemovedBy string
}

// Validate checks that s is internally consistent.
func (s Suppression) Validate() error {
	var errs validation.Errors

	if s.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !s.Scope.Valid() {
		errs = errs.Add("scope", "must be a recognized suppression scope")
	}
	if s.ScopeID == uuid.Nil {
		errs = errs.Add("scope_id", "must not be empty")
	}
	if strings.TrimSpace(s.Reason) == "" {
		errs = errs.Add("reason", "must not be empty")
	}
	if strings.TrimSpace(s.CreatedBy) == "" {
		errs = errs.Add("created_by", "must not be empty")
	}

	return errs.ErrOrNil()
}

// Active reports whether s is currently in effect as of now — not
// explicitly removed, and (if it has an expiration) not yet expired.
func (s Suppression) Active(now time.Time) bool {
	if s.RemovedAt != nil {
		return false
	}
	if s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) {
		return false
	}
	return true
}
