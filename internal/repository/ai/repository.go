// Package ai implements persistence for the AI-assistant domain model
// (internal/domain/ai) — mirroring internal/repository/correlation's
// shape and conventions exactly (one PostgresRepository type implementing
// several narrow, entity-specific interfaces). It never imports
// internal/ai (the engine) — the engine's own Context/Fact/Result values
// are never persisted directly, only the already-reduced
// internal/domain/ai representation (Session/Message/Request/Response/
// ToolCall), the same engine/repository boundary
// internal/repository/correlation keeps with internal/correlation.
package ai

import (
	"context"

	"github.com/google/uuid"

	"ai-surface-platform/internal/domain/ai"
	"ai-surface-platform/internal/repository/pagination"
)

// SessionListFilter narrows a session listing.
type SessionListFilter struct {
	TargetID        uuid.UUID
	InvestigationID uuid.UUID
	UserID          string
	Pagination      pagination.Params
}

// SessionRepository persists and queries ai_sessions rows.
type SessionRepository interface {
	CreateSession(ctx context.Context, s ai.Session) (ai.Session, error)
	GetSessionByID(ctx context.Context, id uuid.UUID) (ai.Session, error)
	ListSessions(ctx context.Context, filter SessionListFilter) (pagination.Page[ai.Session], error)
	// TouchSession refreshes UpdatedAt — called whenever a message is
	// appended, so a session listing can be ordered by recent activity.
	TouchSession(ctx context.Context, id uuid.UUID) error
	// DeleteSession removes the session row and its messages entirely
	// (phase13.md §51's "clear session context" — never touches
	// investigation data, evidence, or the audit trail in ai_requests/
	// ai_responses/ai_tool_calls, which reference the session only by id
	// and survive its deletion for audit purposes).
	DeleteSession(ctx context.Context, id uuid.UUID) error
}

// MessageRepository persists and queries ai_messages rows.
type MessageRepository interface {
	AddMessage(ctx context.Context, m ai.Message) (ai.Message, error)
	// ListMessages returns a session's messages, oldest first, bounded by
	// limit (phase13.md §50: "conversation history must be bounded").
	ListMessages(ctx context.Context, sessionID uuid.UUID, limit int) ([]ai.Message, error)
	// ClearMessages deletes every message for sessionID without deleting
	// the session row itself (phase13.md §51).
	ClearMessages(ctx context.Context, sessionID uuid.UUID) error
}

// RequestListFilter narrows a request listing.
type RequestListFilter struct {
	TargetID        uuid.UUID
	InvestigationID uuid.UUID
	SessionID       uuid.UUID
	Pagination      pagination.Params
}

// RequestRepository persists and queries ai_requests rows — half of
// phase13.md §52's "AI request history" / §53's audit trail.
type RequestRepository interface {
	CreateRequest(ctx context.Context, r ai.Request) (ai.Request, error)
	GetRequestByID(ctx context.Context, id uuid.UUID) (ai.Request, error)
	ListRequests(ctx context.Context, filter RequestListFilter) (pagination.Page[ai.Request], error)
}

// ResponseRepository persists and queries ai_responses rows — the other
// half of the AI request/response audit trail.
type ResponseRepository interface {
	CreateResponse(ctx context.Context, r ai.Response) (ai.Response, error)
	GetResponseByRequestID(ctx context.Context, requestID uuid.UUID) (ai.Response, error)
}

// ToolCallListFilter narrows a tool-call listing.
type ToolCallListFilter struct {
	TargetID   uuid.UUID
	SessionID  uuid.UUID
	Tool       string
	Pagination pagination.Params
}

// ToolCallRepository persists and queries ai_tool_calls rows — phase13.md
// §34's mandatory tool-invocation audit trail.
type ToolCallRepository interface {
	RecordToolCall(ctx context.Context, c ai.ToolCall) (ai.ToolCall, error)
	ListToolCalls(ctx context.Context, filter ToolCallListFilter) (pagination.Page[ai.ToolCall], error)
}
