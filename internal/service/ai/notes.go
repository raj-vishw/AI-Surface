package ai

import (
	"context"

	"github.com/google/uuid"

	domaininvestigation "ai-recon-platform/internal/domain/investigation"
)

// SaveNoteFromResponse implements phase13.md §44 — saves AI-generated
// content as a draft investigation note, explicitly flagged AIGenerated
// and never pre-approved (phase13.md §45: analyst approval is always a
// distinct, later action — see ApproveNote).
func (s *Service) SaveNoteFromResponse(ctx context.Context, investigationID uuid.UUID, authorID, content string) (domaininvestigation.Note, error) {
	note := domaininvestigation.Note{InvestigationID: investigationID, AuthorID: authorID, Content: content, AIGenerated: true}
	if err := note.Validate(); err != nil {
		return domaininvestigation.Note{}, err
	}
	saved, err := s.notes.AddNote(ctx, note)
	if err != nil {
		return domaininvestigation.Note{}, err
	}

	event := domaininvestigation.TimelineEvent{
		TargetID: uuid.Nil, InvestigationID: investigationID, Timestamp: saved.CreatedAt,
		Type: domaininvestigation.EventAINoteCreated, SourceType: domaininvestigation.EntityInvestigation,
		SourceID: &investigationID, Title: "AI-generated note saved as draft", Actor: "ai:" + authorID,
	}
	if inv, err := s.investigations.GetByID(ctx, investigationID); err == nil {
		event.TargetID = inv.TargetID
		if _, err := s.timeline.AppendEvent(ctx, event); err != nil {
			s.logger.Error("ai_note_timeline_audit_failed", "investigation_id", investigationID, "error", err)
		}
	}

	return saved, nil
}

// ApproveNote implements phase13.md §45 — an explicit, distinct analyst
// action; nothing in this package ever calls this automatically.
func (s *Service) ApproveNote(ctx context.Context, noteID uuid.UUID, approvedBy string) (domaininvestigation.Note, error) {
	saved, err := s.notes.ApproveNote(ctx, noteID, approvedBy)
	if err != nil {
		return domaininvestigation.Note{}, err
	}

	event := domaininvestigation.TimelineEvent{
		InvestigationID: saved.InvestigationID, Timestamp: *saved.ApprovedAt,
		Type: domaininvestigation.EventAINoteApproved, SourceType: domaininvestigation.EntityInvestigation,
		SourceID: &saved.InvestigationID, Title: "AI-generated note approved", Actor: approvedBy,
	}
	if inv, err := s.investigations.GetByID(ctx, saved.InvestigationID); err == nil {
		event.TargetID = inv.TargetID
		if _, err := s.timeline.AppendEvent(ctx, event); err != nil {
			s.logger.Error("ai_note_approval_timeline_audit_failed", "note_id", noteID, "error", err)
		}
	}

	return saved, nil
}
