package ai

import (
	"time"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/validation"
)

// Session lets an analyst continue asking questions about one Target — and
// usually one Investigation — without repeating context on every request
// (phase13.md §8). InvestigationID is optional: a session opened to
// explain a single alert or detection need not belong to any
// investigation yet.
type Session struct {
	ID       uuid.UUID
	TargetID uuid.UUID

	// InvestigationID scopes the session to one Phase 9 investigation when
	// set — every message, context build, and tool call in this session
	// is then additionally bound to that investigation's own evidence
	// (phase13.md §50: "investigation-scoped").
	InvestigationID *uuid.UUID

	// UserID is a plain analyst-supplied identifier — see the package doc
	// comment on why this platform has no authenticated principal.
	UserID string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks that s is internally consistent.
func (s Session) Validate() error {
	var errs validation.Errors

	if s.TargetID == uuid.Nil {
		errs = errs.Add("target_id", "must not be empty")
	}
	if !nilOrValidUUID(s.InvestigationID) {
		errs = errs.Add("investigation_id", "must not be the nil UUID when set")
	}
	if !trimmedNotEmpty(s.UserID) {
		errs = errs.Add("user_id", "must not be empty")
	}

	return errs.ErrOrNil()
}
