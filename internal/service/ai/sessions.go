package ai

import (
	"context"

	"github.com/google/uuid"

	domainai "ai-recon-platform/internal/domain/ai"
	airepo "ai-recon-platform/internal/repository/ai"
	"ai-recon-platform/internal/repository/pagination"
)

// CreateSession implements phase13.md §8 — a session may optionally be
// scoped to one investigation from the moment it is opened.
func (s *Service) CreateSession(ctx context.Context, targetID uuid.UUID, investigationID *uuid.UUID, userID string) (domainai.Session, error) {
	sess := domainai.Session{TargetID: targetID, InvestigationID: investigationID, UserID: userID}
	if err := sess.Validate(); err != nil {
		return domainai.Session{}, err
	}
	return s.sessions.CreateSession(ctx, sess)
}

// GetSession returns one session by id.
func (s *Service) GetSession(ctx context.Context, id uuid.UUID) (domainai.Session, error) {
	return s.sessions.GetSessionByID(ctx, id)
}

// ListSessions lists sessions matching filter.
func (s *Service) ListSessions(ctx context.Context, filter airepo.SessionListFilter) (pagination.Page[domainai.Session], error) {
	return s.sessions.ListSessions(ctx, filter)
}

// DeleteSession implements phase13.md §51 — deletes the session and its
// messages entirely, never touching investigation data, evidence, or the
// ai_requests/ai_responses/ai_tool_calls audit trail (which reference the
// session by id and survive its deletion).
func (s *Service) DeleteSession(ctx context.Context, id uuid.UUID) error {
	return s.sessions.DeleteSession(ctx, id)
}

// ClearSession implements phase13.md §51's "clear session context"
// distinctly from DeleteSession — the session row (and therefore its id,
// target, and investigation scoping) survives; only its message history
// is wiped.
func (s *Service) ClearSession(ctx context.Context, id uuid.UUID) error {
	return s.messages.ClearMessages(ctx, id)
}

// AddMessage implements phase13.md §9 — appends one message and refreshes
// the session's UpdatedAt so listings can order by recent activity.
func (s *Service) AddMessage(ctx context.Context, sessionID uuid.UUID, role domainai.Role, content string) (domainai.Message, error) {
	m := domainai.Message{SessionID: sessionID, Role: role, Content: content}
	if err := m.Validate(); err != nil {
		return domainai.Message{}, err
	}
	saved, err := s.messages.AddMessage(ctx, m)
	if err != nil {
		return domainai.Message{}, err
	}
	if err := s.sessions.TouchSession(ctx, sessionID); err != nil {
		s.logger.Error("ai_session_touch_failed", "session_id", sessionID, "error", err)
	}
	return saved, nil
}

// ListMessages returns a session's bounded message history, oldest first
// (phase13.md §50: "conversation history must be bounded").
func (s *Service) ListMessages(ctx context.Context, sessionID uuid.UUID, limit int) ([]domainai.Message, error) {
	return s.messages.ListMessages(ctx, sessionID, limit)
}

// Chat implements phase13.md §48/§49: records the analyst's question,
// runs ChatReply against the session's own bounded context, and records
// the assistant's answer — all three as ordinary session messages plus
// the usual Request/Response audit trail (via ChatReply -> runTask).
func (s *Service) Chat(ctx context.Context, sessionID uuid.UUID, question, provider string) (domainai.Message, error) {
	sess, err := s.sessions.GetSessionByID(ctx, sessionID)
	if err != nil {
		return domainai.Message{}, err
	}
	if _, err := s.AddMessage(ctx, sessionID, domainai.RoleUser, question); err != nil {
		return domainai.Message{}, err
	}

	req := TaskRequest{TargetID: sess.TargetID, InvestigationID: sess.InvestigationID, SessionID: &sessionID, UserID: sess.UserID, Provider: provider}
	result, err := s.ChatReply(ctx, req, question)
	if err != nil {
		return domainai.Message{}, err
	}

	return s.AddMessage(ctx, sessionID, domainai.RoleAssistant, result.Content)
}
