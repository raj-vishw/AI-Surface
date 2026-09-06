package investigation

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"ai-recon-platform/internal/domain/validation"
)

// Note is one analyst annotation on an investigation (phase9.md §26).
// Immutable once created — "notes should be immutable in history"
// (phase9.md §26) is satisfied here in the simplest safe way: there is no
// UpdateNote operation at all. An analyst who wants to correct or extend
// a note adds a new one; the original stays exactly as written, so the
// investigation's history is never silently rewritten.
//
// AIGenerated/ApprovedBy/ApprovedAt are Phase 13 additions (phase13.md
// §44/§45) — the one deliberate, narrow exception to the immutability
// rule above: ApproveNote (see NoteRepository) may set ApprovedBy/
// ApprovedAt after creation, but Content itself is still never rewritten.
// An AI-generated note is never automatically marked approved — that is
// always a distinct, explicit analyst action.
type Note struct {
	ID              uuid.UUID
	InvestigationID uuid.UUID
	AuthorID        string

	Content string

	AIGenerated bool
	ApprovedBy  *string
	ApprovedAt  *time.Time

	CreatedAt time.Time
}

// Validate checks that n is internally consistent.
func (n Note) Validate() error {
	var errs validation.Errors

	if n.InvestigationID == uuid.Nil {
		errs = errs.Add("investigation_id", "must not be empty")
	}
	if strings.TrimSpace(n.AuthorID) == "" {
		errs = errs.Add("author_id", "must not be empty")
	}
	if strings.TrimSpace(n.Content) == "" {
		errs = errs.Add("content", "must not be empty")
	}

	return errs.ErrOrNil()
}
