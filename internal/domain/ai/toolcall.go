package ai

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// ToolCall is a persisted audit record of one AI tool invocation
// (phase13.md §34) — recorded whether the call succeeded, failed, or was
// denied. Arguments/results here are always the already-redacted,
// already-bounded values the tool actually saw/returned — this table
// never carries a secret (phase13.md §34's "do not store secrets").
type ToolCall struct {
	ID uuid.UUID

	SessionID *uuid.UUID
	RequestID *uuid.UUID
	TargetID  uuid.UUID

	// UserID is a plain analyst-supplied identifier — see the package doc
	// comment.
	UserID string

	Tool string
	// Arguments is a small, JSON-serializable map of the (validated,
	// non-secret) arguments the tool was called with.
	Arguments map[string]any

	ResultStatus ToolResultStatus
	// ResultSummary is a short, human-readable outcome description (e.g.
	// "returned 3 findings") — never the full tool result payload, which
	// is reconstructible from the underlying platform data itself.
	ResultSummary string
	Error         string

	CreatedAt time.Time
}

// Validate checks that c is internally consistent.
func (c ToolCall) Validate() error {
	var errs validation.Errors

	if c.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !nilOrValidUUID(c.SessionID) {
		errs = errs.Add("session_id", "must not be the nil UUID when set")
	}
	if !nilOrValidUUID(c.RequestID) {
		errs = errs.Add("request_id", "must not be the nil UUID when set")
	}
	if !trimmedNotEmpty(c.UserID) {
		errs = errs.Add("user_id", "must not be empty")
	}
	if !trimmedNotEmpty(c.Tool) {
		errs = errs.Add("tool", "must not be empty")
	}
	if !c.ResultStatus.Valid() {
		errs = errs.Add("result_status", "must be a recognized tool result status")
	}

	return errs.ErrOrNil()
}
