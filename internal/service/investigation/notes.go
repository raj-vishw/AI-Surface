package investigation

import (
	"context"

	"github.com/google/uuid"

	domaininvestigation "ai-surface-platform/internal/domain/investigation"
)

// AddNote records an immutable analyst note (phase9.md §26) and an
// analyst_note timeline entry.
func (s *Service) AddNote(ctx context.Context, investigationID uuid.UUID, authorID, content string) (domaininvestigation.Note, error) {
	n := domaininvestigation.Note{InvestigationID: investigationID, AuthorID: authorID, Content: content}
	if err := n.Validate(); err != nil {
		return domaininvestigation.Note{}, err
	}
	result, err := s.notes.AddNote(ctx, n)
	if err != nil {
		return domaininvestigation.Note{}, err
	}
	if inv, err := s.investigations.GetByID(ctx, investigationID); err == nil {
		nid := result.ID
		s.recordEvent(ctx, inv, domaininvestigation.EventAnalystNote, "Note added.", "", authorID, &nid)
	}
	return result, nil
}

// ListNotes returns every note for an investigation, oldest first.
func (s *Service) ListNotes(ctx context.Context, investigationID uuid.UUID) ([]domaininvestigation.Note, error) {
	return s.notes.ListNotes(ctx, investigationID)
}
