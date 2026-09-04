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

var (
	_ Repository          = (*PostgresRepository)(nil)
	_ ParameterRepository = (*PostgresRepository)(nil)
	_ EvidenceRepository  = (*PostgresRepository)(nil)
)

const endpointColumns = `
	id, asset_id, scan_id, url, method, scheme, host, port, path, query_pattern,
	content_type, content_length, status_code, response_hash, classification,
	api_type, api_version, sources, confidence, documented, observed, inferred,
	first_seen, last_seen, status, metadata, created_at, updated_at`

func scanEndpoint(row pgx.Row) (endpoint.Endpoint, error) {
	var (
		e             endpoint.Endpoint
		scanID        pgtype.UUID
		contentType   pgtype.Text
		contentLength pgtype.Int8
		statusCode    pgtype.Int4
		responseHash  pgtype.Text
	)
	err := row.Scan(
		&e.ID, &e.AssetID, &scanID, &e.URL, &e.Method, &e.Scheme, &e.Host, &e.Port, &e.Path, &e.QueryPattern,
		&contentType, &contentLength, &statusCode, &responseHash, &e.Classification,
		&e.APIType, &e.APIVersion, &e.Sources, &e.Confidence, &e.Documented, &e.Observed, &e.Inferred,
		&e.FirstSeen, &e.LastSeen, &e.Status, &e.Metadata, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return endpoint.Endpoint{}, err
	}
	e.ScanID = uuidPtr(scanID)
	e.ContentType = contentType.String
	if contentLength.Valid {
		e.ContentLength = &contentLength.Int64
	}
	if statusCode.Valid {
		code := int(statusCode.Int32)
		e.StatusCode = &code
	}
	e.ResponseHash = responseHash.String
	return e, nil
}

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

func int8Param(n *int64) pgtype.Int8 {
	if n == nil {
		return pgtype.Int8{Valid: false}
	}
	return pgtype.Int8{Int64: *n, Valid: true}
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
	if e.Classification == "" {
		e.Classification = endpoint.ClassificationUnknown
	}
	if e.Sources == nil {
		e.Sources = []string{}
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO endpoints (
			asset_id, scan_id, url, method, scheme, host, port, path, query_pattern,
			content_type, content_length, status_code, response_hash, classification,
			api_type, api_version, sources, confidence, documented, observed, inferred,
			first_seen, last_seen, status, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			$18, $19, $20, $21, $22, $23, $24, $25
		)
		ON CONFLICT (asset_id, method, url) DO UPDATE SET
			scan_id        = COALESCE(EXCLUDED.scan_id, endpoints.scan_id),
			query_pattern  = EXCLUDED.query_pattern,
			content_type   = COALESCE(EXCLUDED.content_type, endpoints.content_type),
			content_length = COALESCE(EXCLUDED.content_length, endpoints.content_length),
			status_code    = COALESCE(EXCLUDED.status_code, endpoints.status_code),
			response_hash  = COALESCE(EXCLUDED.response_hash, endpoints.response_hash),
			classification = CASE WHEN EXCLUDED.classification = 'unknown' THEN endpoints.classification ELSE EXCLUDED.classification END,
			api_type       = CASE WHEN EXCLUDED.api_type = '' THEN endpoints.api_type ELSE EXCLUDED.api_type END,
			api_version    = CASE WHEN EXCLUDED.api_version = '' THEN endpoints.api_version ELSE EXCLUDED.api_version END,
			sources        = (SELECT array_agg(DISTINCT s ORDER BY s) FROM unnest(endpoints.sources || EXCLUDED.sources) AS s),
			confidence     = GREATEST(endpoints.confidence, EXCLUDED.confidence),
			documented     = endpoints.documented OR EXCLUDED.documented,
			observed       = endpoints.observed OR EXCLUDED.observed,
			inferred       = endpoints.inferred OR EXCLUDED.inferred,
			first_seen     = LEAST(endpoints.first_seen, EXCLUDED.first_seen),
			last_seen      = GREATEST(endpoints.last_seen, EXCLUDED.last_seen),
			metadata       = endpoints.metadata || EXCLUDED.metadata,
			updated_at     = now()
		RETURNING `+endpointColumns+`, (xmax = 0) AS inserted`,
		// query_pattern is NOT NULL DEFAULT '' (an empty pattern is a
		// meaningful value — "no query parameters" — not "unknown"), so it
		// is passed as a plain string rather than through textParam, which
		// would turn "" into SQL NULL.
		e.AssetID, uuidParam(e.ScanID), e.URL, e.Method, e.Scheme, e.Host, e.Port, e.Path, e.QueryPattern,
		textParam(e.ContentType), int8Param(e.ContentLength), int4Param(e.StatusCode), textParam(e.ResponseHash),
		e.Classification, e.APIType, e.APIVersion, e.Sources, e.Confidence, e.Documented, e.Observed, e.Inferred,
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
		e             endpoint.Endpoint
		scanID        pgtype.UUID
		contentType   pgtype.Text
		contentLength pgtype.Int8
		statusCode    pgtype.Int4
		responseHash  pgtype.Text
		inserted      bool
	)
	err := row.Scan(
		&e.ID, &e.AssetID, &scanID, &e.URL, &e.Method, &e.Scheme, &e.Host, &e.Port, &e.Path, &e.QueryPattern,
		&contentType, &contentLength, &statusCode, &responseHash, &e.Classification,
		&e.APIType, &e.APIVersion, &e.Sources, &e.Confidence, &e.Documented, &e.Observed, &e.Inferred,
		&e.FirstSeen, &e.LastSeen, &e.Status, &e.Metadata, &e.CreatedAt, &e.UpdatedAt, &inserted,
	)
	if err != nil {
		return endpoint.Endpoint{}, false, err
	}
	e.ScanID = uuidPtr(scanID)
	e.ContentType = contentType.String
	if contentLength.Valid {
		e.ContentLength = &contentLength.Int64
	}
	if statusCode.Valid {
		code := int(statusCode.Int32)
		e.StatusCode = &code
	}
	e.ResponseHash = responseHash.String
	return e, inserted, nil
}

// UpdateStatus implements Repository.
func (r *PostgresRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status endpoint.Status) (endpoint.Endpoint, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE endpoints SET status = $2, updated_at = now() WHERE id = $1
		RETURNING `+endpointColumns,
		id, status,
	)
	e, err := scanEndpoint(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return endpoint.Endpoint{}, apperrors.NewNotFound("endpoint not found", err)
		}
		return endpoint.Endpoint{}, sqlerr.Translate(err, "updating endpoint status")
	}
	return e, nil
}

// MarkInactiveExcept implements Repository.
func (r *PostgresRepository) MarkInactiveExcept(ctx context.Context, assetID uuid.UUID, stillFound []uuid.UUID) ([]endpoint.Endpoint, error) {
	if stillFound == nil {
		stillFound = []uuid.UUID{}
	}
	rows, err := r.db.Query(ctx, `
		UPDATE endpoints SET status = 'INACTIVE', updated_at = now()
		WHERE asset_id = $1 AND status != 'INACTIVE' AND NOT (id = ANY($2))
		RETURNING `+endpointColumns,
		assetID, stillFound,
	)
	if err != nil {
		return nil, sqlerr.Translate(err, "marking endpoints inactive")
	}
	defer rows.Close()

	var items []endpoint.Endpoint
	for rows.Next() {
		e, scanErr := scanEndpoint(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning endpoint row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, sqlerr.Translate(err, "iterating endpoints")
	}
	return items, nil
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
	if filter.Classification != "" {
		args = append(args, filter.Classification)
		conditions = append(conditions, fmt.Sprintf("classification = $%d", len(args)))
	}
	if filter.ScanID != nil {
		args = append(args, *filter.ScanID)
		conditions = append(conditions, fmt.Sprintf("scan_id = $%d", len(args)))
	}
	if filter.MinConfidence > 0 {
		args = append(args, filter.MinConfidence)
		conditions = append(conditions, fmt.Sprintf("confidence >= $%d", len(args)))
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

const parameterColumns = `id, endpoint_id, name, location, first_seen, last_seen, created_at`

func scanParameter(row pgx.Row) (Parameter, error) {
	var p Parameter
	err := row.Scan(&p.ID, &p.EndpointID, &p.Name, &p.Location, &p.FirstSeen, &p.LastSeen, &p.CreatedAt)
	return p, err
}

// UpsertParameter implements ParameterRepository.
func (r *PostgresRepository) UpsertParameter(ctx context.Context, input ParameterInput) (Parameter, bool, error) {
	observedAt := input.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO endpoint_parameters (endpoint_id, name, location, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (endpoint_id, name, location) DO UPDATE SET
			first_seen = LEAST(endpoint_parameters.first_seen, EXCLUDED.first_seen),
			last_seen  = GREATEST(endpoint_parameters.last_seen, EXCLUDED.last_seen)
		RETURNING `+parameterColumns+`, (xmax = 0) AS inserted`,
		input.EndpointID, input.Name, input.Location, observedAt,
	)

	var (
		p        Parameter
		inserted bool
	)
	err := row.Scan(&p.ID, &p.EndpointID, &p.Name, &p.Location, &p.FirstSeen, &p.LastSeen, &p.CreatedAt, &inserted)
	if err != nil {
		return Parameter{}, false, sqlerr.Translate(err, "upserting endpoint parameter")
	}
	return p, inserted, nil
}

// ListParameters implements ParameterRepository.
func (r *PostgresRepository) ListParameters(ctx context.Context, endpointID uuid.UUID) ([]Parameter, error) {
	rows, err := r.db.Query(ctx, `SELECT `+parameterColumns+` FROM endpoint_parameters WHERE endpoint_id = $1 ORDER BY name, location`, endpointID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing endpoint parameters")
	}
	defer rows.Close()

	var items []Parameter
	for rows.Next() {
		p, scanErr := scanParameter(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning endpoint parameter row")
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return nil, sqlerr.Translate(err, "iterating endpoint parameters")
	}
	return items, nil
}

const endpointEvidenceColumns = `id, endpoint_id, asset_id, scan_id, source, evidence_data, evidence_fingerprint, confidence, observed_at, created_at`

func scanEndpointEvidence(row pgx.Row) (endpoint.Evidence, error) {
	var (
		e          endpoint.Evidence
		scanID     pgtype.UUID
		fp         string
		confidence float64
	)
	err := row.Scan(&e.ID, &e.EndpointID, &e.AssetID, &scanID, &e.Source, &e.EvidenceData, &fp, &confidence, &e.ObservedAt, &e.CreatedAt)
	if err != nil {
		return endpoint.Evidence{}, err
	}
	e.ScanID = uuidPtr(scanID)
	e.Fingerprint = fp
	e.Confidence = confidence
	return e, nil
}

// CreateEvidence implements EvidenceRepository.
func (r *PostgresRepository) CreateEvidence(ctx context.Context, e endpoint.Evidence) (endpoint.Evidence, bool, error) {
	if e.EvidenceData == nil {
		e.EvidenceData = map[string]any{}
	}
	if e.ObservedAt.IsZero() {
		e.ObservedAt = time.Now().UTC()
	}
	fp, err := endpoint.EvidenceFingerprint(e.EvidenceData)
	if err != nil {
		return endpoint.Evidence{}, false, apperrors.NewValidation("computing evidence fingerprint", err)
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO endpoint_evidence (endpoint_id, asset_id, scan_id, source, evidence_data, evidence_fingerprint, confidence, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (endpoint_id, source, evidence_fingerprint) DO NOTHING
		RETURNING `+endpointEvidenceColumns,
		e.EndpointID, e.AssetID, uuidParam(e.ScanID), e.Source, e.EvidenceData, fp, e.Confidence, e.ObservedAt,
	)
	created, err := scanEndpointEvidence(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := r.getEndpointEvidenceByFingerprint(ctx, e.EndpointID, e.Source, fp)
			if getErr != nil {
				return endpoint.Evidence{}, false, getErr
			}
			return existing, false, nil
		}
		return endpoint.Evidence{}, false, sqlerr.Translate(err, "creating endpoint evidence")
	}
	return created, true, nil
}

func (r *PostgresRepository) getEndpointEvidenceByFingerprint(ctx context.Context, endpointID uuid.UUID, source, fingerprint string) (endpoint.Evidence, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+endpointEvidenceColumns+` FROM endpoint_evidence
		WHERE endpoint_id = $1 AND source = $2 AND evidence_fingerprint = $3`,
		endpointID, source, fingerprint,
	)
	e, err := scanEndpointEvidence(row)
	if err != nil {
		return endpoint.Evidence{}, sqlerr.Translate(err, "fetching existing endpoint evidence")
	}
	return e, nil
}

// ListEvidenceByEndpoint implements EvidenceRepository.
func (r *PostgresRepository) ListEvidenceByEndpoint(ctx context.Context, filter EvidenceListFilter) (pagination.Page[endpoint.Evidence], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[endpoint.Evidence]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"endpoint_id = $1"}
	args := []any{filter.EndpointID}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`
		SELECT %s FROM endpoint_evidence
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, endpointEvidenceColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[endpoint.Evidence]{}, sqlerr.Translate(err, "listing endpoint evidence")
	}
	defer rows.Close()

	var items []endpoint.Evidence
	for rows.Next() {
		e, scanErr := scanEndpointEvidence(rows)
		if scanErr != nil {
			return pagination.Page[endpoint.Evidence]{}, sqlerr.Translate(scanErr, "scanning endpoint evidence row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[endpoint.Evidence]{}, sqlerr.Translate(err, "iterating endpoint evidence")
	}

	page := pagination.Page[endpoint.Evidence]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}
