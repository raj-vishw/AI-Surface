package ai

import (
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// Message is one turn in a Session's conversation (phase13.md §9). Like
// investigation.Note, immutable once created — there is no UpdateMessage
// operation; a correction is a new message, never a silent rewrite of
// history.
type Message struct {
	ID        uuid.UUID
	SessionID uuid.UUID

	Role    Role
	Content string

	CreatedAt time.Time
}

// Validate checks that m is internally consistent.
func (m Message) Validate() error {
	var errs validation.Errors

	if m.SessionID == uuid.Nil {
		errs = errs.Add("session_id", "must not be empty")
	}
	if !m.Role.Valid() {
		errs = errs.Add("role", "must be a recognized role")
	}
	if !trimmedNotEmpty(m.Content) {
		errs = errs.Add("content", "must not be empty")
	}

	return errs.ErrOrNil()
}
