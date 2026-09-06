package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"ai-recon-platform/internal/database"
	domainai "ai-recon-platform/internal/domain/ai"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
)

// PostgresRepository implements every interface in this package,
// mirroring internal/repository/correlation.PostgresRepository's shape
// exactly.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var (
	_ SessionRepository  = (*PostgresRepository)(nil)
	_ MessageRepository  = (*PostgresRepository)(nil)
	_ RequestRepository  = (*PostgresRepository)(nil)
	_ ResponseRepository = (*PostgresRepository)(nil)
	_ ToolCallRepository = (*PostgresRepository)(nil)
)

func uuidPtr(v pgtype.UUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := uuid.UUID(v.Bytes)
	return &id
}

func uuidParam(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

func joinAnd(conditions []string) string {
	out := conditions[0]
	for _, c := range conditions[1:] {
		out += " AND " + c
	}
	return out
}

// ---------------------------------------------------------------------
// ai_sessions
// ---------------------------------------------------------------------

const sessionColumns = `id, target_id, investigation_id, user_id, created_at, updated_at`

func scanSession(row pgx.Row) (domainai.Session, error) {
	var (
		s               domainai.Session
		investigationID pgtype.UUID
	)
	err := row.Scan(&s.ID, &s.TargetID, &investigationID, &s.UserID, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return domainai.Session{}, err
	}
	s.InvestigationID = uuidPtr(investigationID)
	return s, nil
}

// CreateSession implements SessionRepository.
func (r *PostgresRepository) CreateSession(ctx context.Context, s domainai.Session) (domainai.Session, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO ai_sessions (target_id, investigation_id, user_id)
		VALUES ($1,$2,$3)
		RETURNING `+sessionColumns,
		s.TargetID, uuidParam(s.InvestigationID), s.UserID)
	result, err := scanSession(row)
	if err != nil {
		return domainai.Session{}, apperrors.NewDatabase("creating AI session", err)
	}
	return result, nil
}

// GetSessionByID implements SessionRepository.
func (r *PostgresRepository) GetSessionByID(ctx context.Context, id uuid.UUID) (domainai.Session, error) {
	row := r.db.QueryRow(ctx, `SELECT `+sessionColumns+` FROM ai_sessions WHERE id = $1`, id)
	result, err := scanSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domainai.Session{}, apperrors.NewNotFound("AI session not found", err)
		}
		return domainai.Session{}, apperrors.NewDatabase("fetching AI session", err)
	}
	return result, nil
}

// ListSessions implements SessionRepository.
func (r *PostgresRepository) ListSessions(ctx context.Context, filter SessionListFilter) (pagination.Page[domainai.Session], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[domainai.Session]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		conditions = append(conditions, fmt.Sprintf(clause, len(args)))
	}
	if filter.TargetID != uuid.Nil {
		add("target_id = $%d", filter.TargetID)
	}
	if filter.InvestigationID != uuid.Nil {
		add("investigation_id = $%d", filter.InvestigationID)
	}
	if filter.UserID != "" {
		add("user_id = $%d", filter.UserID)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM ai_sessions WHERE %s ORDER BY created_at, id LIMIT $%d`, sessionColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[domainai.Session]{}, apperrors.NewDatabase("listing AI sessions", err)
	}
	defer rows.Close()

	var items []domainai.Session
	for rows.Next() {
		s, scanErr := scanSession(rows)
		if scanErr != nil {
			return pagination.Page[domainai.Session]{}, apperrors.NewDatabase("scanning AI session row", scanErr)
		}
		items = append(items, s)
	}
	page := pagination.Page[domainai.Session]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	if rows.Err() != nil {
		return pagination.Page[domainai.Session]{}, apperrors.NewDatabase("iterating AI sessions", rows.Err())
	}
	return page, nil
}

// TouchSession implements SessionRepository.
func (r *PostgresRepository) TouchSession(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE ai_sessions SET updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return apperrors.NewDatabase("touching AI session", err)
	}
	return nil
}

// DeleteSession implements SessionRepository.
func (r *PostgresRepository) DeleteSession(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM ai_sessions WHERE id = $1`, id)
	if err != nil {
		return apperrors.NewDatabase("deleting AI session", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// ai_messages
// ---------------------------------------------------------------------

const messageColumns = `id, session_id, role, content, created_at`

func scanMessage(row pgx.Row) (domainai.Message, error) {
	var m domainai.Message
	err := row.Scan(&m.ID, &m.SessionID, &m.Role, &m.Content, &m.CreatedAt)
	return m, err
}

// AddMessage implements MessageRepository.
func (r *PostgresRepository) AddMessage(ctx context.Context, m domainai.Message) (domainai.Message, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO ai_messages (session_id, role, content)
		VALUES ($1,$2,$3)
		RETURNING `+messageColumns,
		m.SessionID, m.Role, m.Content)
	result, err := scanMessage(row)
	if err != nil {
		return domainai.Message{}, apperrors.NewDatabase("adding AI message", err)
	}
	return result, nil
}

// ListMessages implements MessageRepository.
func (r *PostgresRepository) ListMessages(ctx context.Context, sessionID uuid.UUID, limit int) ([]domainai.Message, error) {
	if limit <= 0 {
		limit = pagination.DefaultLimit
	}
	rows, err := r.db.Query(ctx, `
		SELECT `+messageColumns+` FROM (
			SELECT * FROM ai_messages WHERE session_id = $1 ORDER BY created_at DESC LIMIT $2
		) recent ORDER BY created_at ASC`, sessionID, limit)
	if err != nil {
		return nil, apperrors.NewDatabase("listing AI messages", err)
	}
	defer rows.Close()
	var out []domainai.Message
	for rows.Next() {
		m, scanErr := scanMessage(rows)
		if scanErr != nil {
			return nil, apperrors.NewDatabase("scanning AI message row", scanErr)
		}
		out = append(out, m)
	}
	if rows.Err() != nil {
		return nil, apperrors.NewDatabase("iterating AI messages", rows.Err())
	}
	return out, nil
}

// ClearMessages implements MessageRepository.
func (r *PostgresRepository) ClearMessages(ctx context.Context, sessionID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM ai_messages WHERE session_id = $1`, sessionID)
	if err != nil {
		return apperrors.NewDatabase("clearing AI messages", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// ai_requests
// ---------------------------------------------------------------------

const requestColumns = `id, target_id, session_id, investigation_id, user_id, task_type, instructions, prompt_version, context_hash, created_at`

func scanRequest(row pgx.Row) (domainai.Request, error) {
	var (
		req                      domainai.Request
		sessionID, investigation pgtype.UUID
	)
	err := row.Scan(&req.ID, &req.TargetID, &sessionID, &investigation, &req.UserID, &req.TaskType,
		&req.Instructions, &req.PromptVersion, &req.ContextHash, &req.CreatedAt)
	if err != nil {
		return domainai.Request{}, err
	}
	req.SessionID = uuidPtr(sessionID)
	req.InvestigationID = uuidPtr(investigation)
	return req, nil
}

// CreateRequest implements RequestRepository.
func (r *PostgresRepository) CreateRequest(ctx context.Context, req domainai.Request) (domainai.Request, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO ai_requests (target_id, session_id, investigation_id, user_id, task_type, instructions, prompt_version, context_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING `+requestColumns,
		req.TargetID, uuidParam(req.SessionID), uuidParam(req.InvestigationID), req.UserID, req.TaskType,
		req.Instructions, req.PromptVersion, req.ContextHash)
	result, err := scanRequest(row)
	if err != nil {
		return domainai.Request{}, apperrors.NewDatabase("creating AI request", err)
	}
	return result, nil
}

// GetRequestByID implements RequestRepository.
func (r *PostgresRepository) GetRequestByID(ctx context.Context, id uuid.UUID) (domainai.Request, error) {
	row := r.db.QueryRow(ctx, `SELECT `+requestColumns+` FROM ai_requests WHERE id = $1`, id)
	result, err := scanRequest(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domainai.Request{}, apperrors.NewNotFound("AI request not found", err)
		}
		return domainai.Request{}, apperrors.NewDatabase("fetching AI request", err)
	}
	return result, nil
}

// ListRequests implements RequestRepository.
func (r *PostgresRepository) ListRequests(ctx context.Context, filter RequestListFilter) (pagination.Page[domainai.Request], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[domainai.Request]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		conditions = append(conditions, fmt.Sprintf(clause, len(args)))
	}
	if filter.TargetID != uuid.Nil {
		add("target_id = $%d", filter.TargetID)
	}
	if filter.InvestigationID != uuid.Nil {
		add("investigation_id = $%d", filter.InvestigationID)
	}
	if filter.SessionID != uuid.Nil {
		add("session_id = $%d", filter.SessionID)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM ai_requests WHERE %s ORDER BY created_at, id LIMIT $%d`, requestColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[domainai.Request]{}, apperrors.NewDatabase("listing AI requests", err)
	}
	defer rows.Close()

	var items []domainai.Request
	for rows.Next() {
		req, scanErr := scanRequest(rows)
		if scanErr != nil {
			return pagination.Page[domainai.Request]{}, apperrors.NewDatabase("scanning AI request row", scanErr)
		}
		items = append(items, req)
	}
	page := pagination.Page[domainai.Request]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	if rows.Err() != nil {
		return pagination.Page[domainai.Request]{}, apperrors.NewDatabase("iterating AI requests", rows.Err())
	}
	return page, nil
}

// ---------------------------------------------------------------------
// ai_responses
// ---------------------------------------------------------------------

const responseColumns = `id, request_id, content, model, provider, prompt_version, confidence, citations, response_hash, input_tokens, output_tokens, latency_ms, created_at`

func scanResponse(row pgx.Row) (domainai.Response, error) {
	var (
		resp          domainai.Response
		citationsJSON []byte
	)
	err := row.Scan(&resp.ID, &resp.RequestID, &resp.Content, &resp.Model, &resp.Provider, &resp.PromptVersion,
		&resp.Confidence, &citationsJSON, &resp.ResponseHash, &resp.InputTokens, &resp.OutputTokens, &resp.LatencyMS, &resp.CreatedAt)
	if err != nil {
		return domainai.Response{}, err
	}
	if len(citationsJSON) > 0 {
		if err := json.Unmarshal(citationsJSON, &resp.Citations); err != nil {
			return domainai.Response{}, fmt.Errorf("decoding citations: %w", err)
		}
	}
	return resp, nil
}

// CreateResponse implements ResponseRepository.
func (r *PostgresRepository) CreateResponse(ctx context.Context, resp domainai.Response) (domainai.Response, error) {
	citationsJSON, err := json.Marshal(nonNilStrings(resp.Citations))
	if err != nil {
		return domainai.Response{}, fmt.Errorf("encoding citations: %w", err)
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO ai_responses (request_id, content, model, provider, prompt_version, confidence, citations, response_hash, input_tokens, output_tokens, latency_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING `+responseColumns,
		resp.RequestID, resp.Content, resp.Model, resp.Provider, resp.PromptVersion, resp.Confidence,
		citationsJSON, resp.ResponseHash, resp.InputTokens, resp.OutputTokens, resp.LatencyMS)
	result, err := scanResponse(row)
	if err != nil {
		return domainai.Response{}, apperrors.NewDatabase("creating AI response", err)
	}
	return result, nil
}

// GetResponseByRequestID implements ResponseRepository.
func (r *PostgresRepository) GetResponseByRequestID(ctx context.Context, requestID uuid.UUID) (domainai.Response, error) {
	row := r.db.QueryRow(ctx, `SELECT `+responseColumns+` FROM ai_responses WHERE request_id = $1`, requestID)
	result, err := scanResponse(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domainai.Response{}, apperrors.NewNotFound("AI response not found", err)
		}
		return domainai.Response{}, apperrors.NewDatabase("fetching AI response", err)
	}
	return result, nil
}

func nonNilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// ---------------------------------------------------------------------
// ai_tool_calls
// ---------------------------------------------------------------------

const toolCallColumns = `id, session_id, request_id, target_id, user_id, tool, arguments, result_status, result_summary, error, created_at`

func scanToolCall(row pgx.Row) (domainai.ToolCall, error) {
	var (
		c                    domainai.ToolCall
		sessionID, requestID pgtype.UUID
		argsJSON             []byte
	)
	err := row.Scan(&c.ID, &sessionID, &requestID, &c.TargetID, &c.UserID, &c.Tool, &argsJSON,
		&c.ResultStatus, &c.ResultSummary, &c.Error, &c.CreatedAt)
	if err != nil {
		return domainai.ToolCall{}, err
	}
	c.SessionID = uuidPtr(sessionID)
	c.RequestID = uuidPtr(requestID)
	if len(argsJSON) > 0 {
		if err := json.Unmarshal(argsJSON, &c.Arguments); err != nil {
			return domainai.ToolCall{}, fmt.Errorf("decoding tool call arguments: %w", err)
		}
	}
	return c, nil
}

// RecordToolCall implements ToolCallRepository.
func (r *PostgresRepository) RecordToolCall(ctx context.Context, c domainai.ToolCall) (domainai.ToolCall, error) {
	if c.Arguments == nil {
		c.Arguments = map[string]any{}
	}
	argsJSON, err := json.Marshal(c.Arguments)
	if err != nil {
		return domainai.ToolCall{}, fmt.Errorf("encoding tool call arguments: %w", err)
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO ai_tool_calls (session_id, request_id, target_id, user_id, tool, arguments, result_status, result_summary, error)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING `+toolCallColumns,
		uuidParam(c.SessionID), uuidParam(c.RequestID), c.TargetID, c.UserID, c.Tool, argsJSON,
		c.ResultStatus, c.ResultSummary, c.Error)
	result, err := scanToolCall(row)
	if err != nil {
		return domainai.ToolCall{}, apperrors.NewDatabase("recording AI tool call", err)
	}
	return result, nil
}

// ListToolCalls implements ToolCallRepository.
func (r *PostgresRepository) ListToolCalls(ctx context.Context, filter ToolCallListFilter) (pagination.Page[domainai.ToolCall], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[domainai.ToolCall]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		conditions = append(conditions, fmt.Sprintf(clause, len(args)))
	}
	if filter.TargetID != uuid.Nil {
		add("target_id = $%d", filter.TargetID)
	}
	if filter.SessionID != uuid.Nil {
		add("session_id = $%d", filter.SessionID)
	}
	if filter.Tool != "" {
		add("tool = $%d", filter.Tool)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM ai_tool_calls WHERE %s ORDER BY created_at, id LIMIT $%d`, toolCallColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[domainai.ToolCall]{}, apperrors.NewDatabase("listing AI tool calls", err)
	}
	defer rows.Close()

	var items []domainai.ToolCall
	for rows.Next() {
		c, scanErr := scanToolCall(rows)
		if scanErr != nil {
			return pagination.Page[domainai.ToolCall]{}, apperrors.NewDatabase("scanning AI tool call row", scanErr)
		}
		items = append(items, c)
	}
	page := pagination.Page[domainai.ToolCall]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	if rows.Err() != nil {
		return pagination.Page[domainai.ToolCall]{}, apperrors.NewDatabase("iterating AI tool calls", rows.Err())
	}
	return page, nil
}
