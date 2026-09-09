package ai

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Request is a persisted record of one AI operation asked for (phase13.md
// §6) — the analyst-facing "instructions" plus enough metadata
// (PromptVersion, ContextHash) to reproduce or audit what was sent, but
// never the full evidence context itself (that is reconstructible from
// ContextHash plus the platform's own already-persisted data — repeating
// it here would be exactly the "duplicate the entire project database"
// phase13.md §12 warns against).
type Request struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	// SessionID/InvestigationID are optional — a one-off "explain this
	// alert" request has neither.
	SessionID       *uuid.UUID
	InvestigationID *uuid.UUID

	// UserID is a plain analyst-supplied identifier — see the package doc
	// comment.
	UserID string

	TaskType TaskType

	// Instructions is the analyst's own free-form ask, if any (e.g. a chat
	// message) — always treated as analyst instruction, never as
	// telemetry data, when building a prompt (internal/ai's trust-boundary
	// discipline — phase13.md §36).
	Instructions string

	// PromptVersion identifies which versioned prompt template produced
	// this request (phase13.md §97) — e.g. "investigation_summary:v1".
	PromptVersion string

	// ContextHash is a hash of the normalized evidence context supplied to
	// the model (phase13.md §100) — allows auditing what context was used
	// without storing the context itself.
	ContextHash string

	CreatedAt time.Time
}

// Validate checks that r is internally consistent.
func (r Request) Validate() error {
	var errs validation.Errors

	if r.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !nilOrValidUUID(r.SessionID) {
		errs = errs.Add("session_id", "must not be the nil UUID when set")
	}
	if !nilOrValidUUID(r.InvestigationID) {
		errs = errs.Add("investigation_id", "must not be the nil UUID when set")
	}
	if !trimmedNotEmpty(r.UserID) {
		errs = errs.Add("user_id", "must not be empty")
	}
	if !r.TaskType.Valid() {
		errs = errs.Add("task_type", "must be a recognized task type")
	}
	if !trimmedNotEmpty(r.PromptVersion) {
		errs = errs.Add("prompt_version", "must not be empty")
	}
	if !trimmedNotEmpty(r.ContextHash) {
		errs = errs.Add("context_hash", "must not be empty")
	}

	return errs.ErrOrNil()
}
