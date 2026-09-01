package endpoint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/domain/endpoint"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/repository/sqlerr"
)

// PostgresRepository is the PostgreSQL-backed Repository implementation. It
// depends on database.Executor rather than *database.Pool directly so the
// same code works both standalone and inside a transaction.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a Repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var _ Repository = (*PostgresRepository)(nil)

const endpointColumns = `
	id, asset_id, url, method, scheme, host, port, path, query_pattern,
	content_type, status_code, response_hash, first_seen, last_seen, status,
	metadata, created_at, updated_at`

func scanEndpoint(row pgx.Row) (endpoint.Endpoint, error) {
	var (
		e            endpoint.Endpoint
		contentType  pgtype.Text
		statusCode   pgtype.Int4
		responseHash pgtype.Text
	)
	err := row.Scan(
		&e.ID, &e.AssetID, &e.URL, &e.Method, &e.Scheme, &e.Host, &e.Port, &e.Path, &e.QueryPattern,
		&contentType, &statusCode, &responseHash, &e.FirstSeen, &e.LastSeen, &e.Status,
		&e.Metadata, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return endpoint.Endpoint{}, err
	}
	e.ContentType = contentType.String
	if statusCode.Valid {
		code := int(statusCode.Int32)
		e.StatusCode = &code
	}
	e.ResponseHash = responseHash.String
	return e, nil
}

func textParam(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

func int4Param(n *int) pgtype.Int4 {
	if n == nil {
		return pgtype.Int4{Valid: false}
	}
	// endpoint.Endpoint.Validate rejects status codes outside 100-599
	// before this is ever called, so the narrowing to int32 is always in
	// range.
	return pgtype.Int4{Int32: int32(*n), Valid: true} //nolint:gosec // bounds-checked by domain validation before persistence
}

// Upsert implements Repository. Identity is the database's unique
// constraint on (asset_id, method, url) — the same normalized URL this
// package's domain type requires callers to have already produced via
// endpoint.Normalize before calling Upsert.
func (r *PostgresRepository) Upsert(ctx context.Context, e endpoint.Endpoint) (endpoint.Endpoint, bool, error) {
	if e.FirstSeen.IsZero() {
		e.FirstSeen = time.Now().UTC()
	}
	if e.LastSeen.IsZero() {
		e.LastSeen = e.FirstSeen
	}
	if e.Status == "" {
		e.Status = endpoint.StatusDiscovered
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO endpoints (
			asset_id, url, method, scheme, host, port, path, query_pattern,
			content_type, status_code, response_hash, first_seen, last_seen, status, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)
		ON CONFLICT (asset_id, method, url) DO UPDATE SET
			query_pattern = EXCLUDED.query_pattern,
			content_type  = COALESCE(EXCLUDED.content_type, endpoints.content_type),
			status_code   = COALESCE(EXCLUDED.status_code, endpoints.status_code),
			response_hash = COALESCE(EXCLUDED.response_hash, endpoints.response_hash),
			first_seen    = LEAST(endpoints.first_seen, EXCLUDED.first_seen),
			last_seen     = GREATEST(endpoints.last_seen, EXCLUDED.last_seen),
			metadata      = endpoints.metadata || EXCLUDED.metadata,
			updated_at    = now()
		RETURNING `+endpointColumns+`, (xmax = 0) AS inserted`,
		// query_pattern is NOT NULL DEFAULT '' (an empty pattern is a
		// meaningful value — "no query parameters" — not "unknown"), so it
		// is passed as a plain string rather than through textParam, which
		// would turn "" into SQL NULL.
		e.AssetID, e.URL, e.Method, e.Scheme, e.Host, e.Port, e.Path, e.QueryPattern,
		textParam(e.ContentType), int4Param(e.StatusCode), textParam(e.ResponseHash),
		e.FirstSeen, e.LastSeen, e.Status, e.Metadata,
	)

	result, created, err := scanUpsertedEndpoint(row)
	if err != nil {
		return endpoint.Endpoint{}, false, sqlerr.Translate(err, "upserting endpoint")
	}
	return result, created, nil
}

func scanUpsertedEndpoint(row pgx.Row) (endpoint.Endpoint, bool, error) {
	var (
		e            endpoint.Endpoint
		contentType  pgtype.Text
		statusCode   pgtype.Int4
		responseHash pgtype.Text
		inserted     bool
	)
	err := row.Scan(
		&e.ID, &e.AssetID, &e.URL, &e.Method, &e.Scheme, &e.Host, &e.Port, &e.Path, &e.QueryPattern,
		&contentType, &statusCode, &responseHash, &e.FirstSeen, &e.LastSeen, &e.Status,
		&e.Metadata, &e.CreatedAt, &e.UpdatedAt, &inserted,
	)
	if err != nil {
		return endpoint.Endpoint{}, false, err
	}
	e.ContentType = contentType.String
	if statusCode.Valid {
		code := int(statusCode.Int32)
		e.StatusCode = &code
	}
	e.ResponseHash = responseHash.String
	return e, inserted, nil
}

// GetByID implements Repository.
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (endpoint.Endpoint, error) {
	row := r.db.QueryRow(ctx, `SELECT `+endpointColumns+` FROM endpoints WHERE id = $1`, id)
	e, err := scanEndpoint(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return endpoint.Endpoint{}, apperrors.NewNotFound("endpoint not found", err)
		}
		return endpoint.Endpoint{}, sqlerr.Translate(err, "fetching endpoint")
	}
	return e, nil
}

// ListByAsset implements Repository.
func (r *PostgresRepository) ListByAsset(ctx context.Context, filter ListFilter) (pagination.Page[endpoint.Endpoint], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[endpoint.Endpoint]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"asset_id = $1"}
	args := []any{filter.AssetID}
	if filter.Status != "" {
		args = append(args, filter.Status)
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`
		SELECT %s FROM endpoints
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, endpointColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[endpoint.Endpoint]{}, sqlerr.Translate(err, "listing endpoints")
	}
	defer rows.Close()

	var items []endpoint.Endpoint
	for rows.Next() {
		e, scanErr := scanEndpoint(rows)
		if scanErr != nil {
			return pagination.Page[endpoint.Endpoint]{}, sqlerr.Translate(scanErr, "scanning endpoint row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[endpoint.Endpoint]{}, sqlerr.Translate(err, "iterating endpoints")
	}

	page := pagination.Page[endpoint.Endpoint]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

func joinAnd(conditions []string) string {
	out := conditions[0]
	for _, c := range conditions[1:] {
		out += " AND " + c
	}
	return out
}
