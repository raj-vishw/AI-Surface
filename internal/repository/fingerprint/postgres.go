package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/domain/fingerprint"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/repository/sqlerr"
)

// PostgresRepository implements both Repository and EvidenceRepository,
// mirroring internal/repository/asset.PostgresRepository's shape exactly
// — it depends on database.Executor so the same code works standalone or
// inside a transaction.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var (
	_ Repository         = (*PostgresRepository)(nil)
	_ EvidenceRepository = (*PostgresRepository)(nil)
)

const fingerprintColumns = `
	id, asset_id, target_id, scan_id, category, technology, product, vendor,
	version, confidence, status, identity_key, metadata, first_seen, last_seen,
	created_at, updated_at`

func scanFingerprint(row pgx.Row) (fingerprint.Fingerprint, error) {
	var (
		f           fingerprint.Fingerprint
		scanID      pgtype.UUID
		confidence  float64
		identityKey string // derived, never stored on the domain struct — see identityKeyOf
	)
	err := row.Scan(
		&f.ID, &f.AssetID, &f.TargetID, &scanID, &f.Category, &f.Technology, &f.Product, &f.Vendor,
		&f.Version, &confidence, &f.Status, &identityKey, &f.Metadata, &f.FirstSeen, &f.LastSeen,
		&f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return fingerprint.Fingerprint{}, err
	}
	f.Confidence = fingerprint.Score(confidence)
	f.ScanID = uuidPtr(scanID)
	return f, nil
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

// GetByID implements Repository.
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (fingerprint.Fingerprint, error) {
	row := r.db.QueryRow(ctx, `SELECT `+fingerprintColumns+` FROM fingerprints WHERE id = $1`, id)
	f, err := scanFingerprint(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fingerprint.Fingerprint{}, apperrors.NewNotFound("fingerprint not found", err)
		}
		return fingerprint.Fingerprint{}, sqlerr.Translate(err, "fetching fingerprint")
	}
	return f, nil
}

// Upsert implements Repository. See the interface doc comment for the
// merge semantics: unlike asset.Upsert, Confidence/Version/Vendor/
// Product/ScanID/Metadata always take the NEW observation's values (not
// a max/merge) — a fingerprint expresses "what we currently believe",
// and a re-analysis that finds weaker evidence than before (e.g. a header
// was removed) must be allowed to lower confidence, not be stuck forever
// at its historical maximum. The full history of every value it has ever
// held lives in fingerprint_evidence, never lost.
func (r *PostgresRepository) Upsert(ctx context.Context, f fingerprint.Fingerprint) (fingerprint.Fingerprint, bool, error) {
	if f.FirstSeen.IsZero() {
		f.FirstSeen = time.Now().UTC()
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = f.FirstSeen
	}
	if f.Status == "" {
		f.Status = fingerprint.StatusActive
	}
	if f.Metadata == nil {
		f.Metadata = map[string]any{}
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO fingerprints (
			asset_id, target_id, scan_id, category, technology, product, vendor,
			version, confidence, status, identity_key, metadata, first_seen, last_seen
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
		ON CONFLICT (asset_id, identity_key) DO UPDATE SET
			scan_id     = EXCLUDED.scan_id,
			product     = EXCLUDED.product,
			vendor      = EXCLUDED.vendor,
			version     = EXCLUDED.version,
			confidence  = EXCLUDED.confidence,
			status      = 'ACTIVE',
			metadata    = EXCLUDED.metadata,
			first_seen  = LEAST(fingerprints.first_seen, EXCLUDED.first_seen),
			last_seen   = GREATEST(fingerprints.last_seen, EXCLUDED.last_seen),
			updated_at  = now()
		RETURNING `+fingerprintColumns+`, (xmax = 0) AS inserted`,
		f.AssetID, f.TargetID, uuidParam(f.ScanID), f.Category, f.Technology, f.Product, f.Vendor,
		f.Version, float64(f.Confidence), f.Status, identityKeyOf(f), f.Metadata, f.FirstSeen, f.LastSeen,
	)

	result, created, err := scanUpsertedFingerprint(row)
	if err != nil {
		return fingerprint.Fingerprint{}, false, sqlerr.Translate(err, "upserting fingerprint")
	}
	return result, created, nil
}

// identityKeyOf computes f's identity key the same way
// internal/domain/fingerprint.IdentityKey does — the repository never
// trusts a caller-supplied field for something that must be derived
// deterministically.
func identityKeyOf(f fingerprint.Fingerprint) string {
	return fingerprint.IdentityKey(f.AssetID, f.Category, f.Technology)
}

func scanUpsertedFingerprint(row pgx.Row) (fingerprint.Fingerprint, bool, error) {
	var (
		f           fingerprint.Fingerprint
		scanID      pgtype.UUID
		confidence  float64
		identityKey string
		inserted    bool
	)
	err := row.Scan(
		&f.ID, &f.AssetID, &f.TargetID, &scanID, &f.Category, &f.Technology, &f.Product, &f.Vendor,
		&f.Version, &confidence, &f.Status, &identityKey, &f.Metadata, &f.FirstSeen, &f.LastSeen,
		&f.CreatedAt, &f.UpdatedAt, &inserted,
	)
	if err != nil {
		return fingerprint.Fingerprint{}, false, err
	}
	f.Confidence = fingerprint.Score(confidence)
	f.ScanID = uuidPtr(scanID)
	return f, inserted, nil
}

// MarkInactive implements Repository.
func (r *PostgresRepository) MarkInactive(ctx context.Context, assetID uuid.UUID, stillMatched []uuid.UUID) ([]fingerprint.Fingerprint, error) {
	rows, err := r.db.Query(ctx, `
		UPDATE fingerprints SET status = 'INACTIVE', updated_at = now()
		WHERE asset_id = $1 AND status = 'ACTIVE' AND NOT (id = ANY($2))
		RETURNING `+fingerprintColumns,
		assetID, stillMatchedParam(stillMatched),
	)
	if err != nil {
		return nil, sqlerr.Translate(err, "marking fingerprints inactive")
	}
	defer rows.Close()

	var items []fingerprint.Fingerprint
	for rows.Next() {
		f, scanErr := scanFingerprint(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning fingerprint row")
		}
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		return nil, sqlerr.Translate(err, "iterating fingerprints")
	}
	return items, nil
}

// stillMatchedParam converts nil/empty into a valid (empty) uuid array
// parameter — "= ANY('{}')" is always false, which is exactly what we
// want: every ACTIVE fingerprint for the asset becomes a MarkInactive
// candidate when nothing matched this run.
func stillMatchedParam(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

// List implements Repository.
func (r *PostgresRepository) List(ctx context.Context, filter ListFilter) (pagination.Page[fingerprint.Fingerprint], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[fingerprint.Fingerprint]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		conditions = append(conditions, fmt.Sprintf(clause, len(args)))
	}

	if filter.AssetID != uuid.Nil {
		add("asset_id = $%d", filter.AssetID)
	}
	if filter.TargetID != uuid.Nil {
		add("target_id = $%d", filter.TargetID)
	}
	if filter.Category != "" {
		add("category = $%d", filter.Category)
	}
	if filter.Technology != "" {
		add("technology = $%d", filter.Technology)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if filter.MinConfidence > 0 {
		add("confidence >= $%d", filter.MinConfidence)
	}
	if filter.ScanID != nil {
		add("scan_id = $%d", *filter.ScanID)
	}
	if !filter.FirstSeenAfter.IsZero() {
		add("first_seen >= $%d", filter.FirstSeenAfter)
	}
	if !filter.LastSeenAfter.IsZero() {
		add("last_seen >= $%d", filter.LastSeenAfter)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, limit+1)
	query := fmt.Sprintf(`
		SELECT %s FROM fingerprints
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, fingerprintColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[fingerprint.Fingerprint]{}, sqlerr.Translate(err, "listing fingerprints")
	}
	defer rows.Close()

	var items []fingerprint.Fingerprint
	for rows.Next() {
		f, scanErr := scanFingerprint(rows)
		if scanErr != nil {
			return pagination.Page[fingerprint.Fingerprint]{}, sqlerr.Translate(scanErr, "scanning fingerprint row")
		}
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[fingerprint.Fingerprint]{}, sqlerr.Translate(err, "iterating fingerprints")
	}

	page := pagination.Page[fingerprint.Fingerprint]{Items: items}
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

const evidenceColumns = `id, fingerprint_id, asset_id, scan_id, source, signals, signals_fingerprint, confidence, observed_at, created_at`

func scanEvidence(row pgx.Row) (fingerprint.Evidence, error) {
	var (
		e           fingerprint.Evidence
		scanID      pgtype.UUID
		signalsJSON []byte
		fp          string
		confidence  float64
	)
	err := row.Scan(&e.ID, &e.FingerprintID, &e.AssetID, &scanID, &e.Source, &signalsJSON, &fp, &confidence, &e.ObservedAt, &e.CreatedAt)
	if err != nil {
		return fingerprint.Evidence{}, err
	}
	if err := json.Unmarshal(signalsJSON, &e.Signals); err != nil {
		return fingerprint.Evidence{}, fmt.Errorf("decoding signals: %w", err)
	}
	e.ScanID = uuidPtr(scanID)
	e.Fingerprint = fp
	e.Confidence = fingerprint.Score(confidence)
	return e, nil
}

// CreateEvidence implements EvidenceRepository.
func (r *PostgresRepository) CreateEvidence(ctx context.Context, e fingerprint.Evidence) (fingerprint.Evidence, bool, error) {
	if e.ObservedAt.IsZero() {
		e.ObservedAt = time.Now().UTC()
	}
	if e.Source == "" {
		e.Source = "fingerprint"
	}
	fp, err := fingerprint.SignalsFingerprint(e.Signals)
	if err != nil {
		return fingerprint.Evidence{}, false, apperrors.NewValidation("computing signals fingerprint", err)
	}
	signalsJSON, err := json.Marshal(e.Signals)
	if err != nil {
		return fingerprint.Evidence{}, false, apperrors.NewValidation("encoding signals", err)
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO fingerprint_evidence (fingerprint_id, asset_id, scan_id, source, signals, signals_fingerprint, confidence, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (fingerprint_id, signals_fingerprint) DO NOTHING
		RETURNING `+evidenceColumns,
		e.FingerprintID, e.AssetID, uuidParam(e.ScanID), e.Source, signalsJSON, fp, float64(e.Confidence), e.ObservedAt,
	)
	created, err := scanEvidence(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := r.getEvidenceByFingerprint(ctx, e.FingerprintID, fp)
			if getErr != nil {
				return fingerprint.Evidence{}, false, getErr
			}
			return existing, false, nil
		}
		return fingerprint.Evidence{}, false, sqlerr.Translate(err, "creating fingerprint evidence")
	}
	return created, true, nil
}

func (r *PostgresRepository) getEvidenceByFingerprint(ctx context.Context, fingerprintID uuid.UUID, signalsFingerprint string) (fingerprint.Evidence, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+evidenceColumns+` FROM fingerprint_evidence
		WHERE fingerprint_id = $1 AND signals_fingerprint = $2`,
		fingerprintID, signalsFingerprint,
	)
	e, err := scanEvidence(row)
	if err != nil {
		return fingerprint.Evidence{}, sqlerr.Translate(err, "fetching existing fingerprint evidence")
	}
	return e, nil
}

// ListEvidenceByFingerprint implements EvidenceRepository.
func (r *PostgresRepository) ListEvidenceByFingerprint(ctx context.Context, filter EvidenceListFilter) (pagination.Page[fingerprint.Evidence], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[fingerprint.Evidence]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"fingerprint_id = $1"}
	args := []any{filter.FingerprintID}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`
		SELECT %s FROM fingerprint_evidence
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, evidenceColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[fingerprint.Evidence]{}, sqlerr.Translate(err, "listing fingerprint evidence")
	}
	defer rows.Close()

	var items []fingerprint.Evidence
	for rows.Next() {
		e, scanErr := scanEvidence(rows)
		if scanErr != nil {
			return pagination.Page[fingerprint.Evidence]{}, sqlerr.Translate(scanErr, "scanning fingerprint evidence row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[fingerprint.Evidence]{}, sqlerr.Translate(err, "iterating fingerprint evidence")
	}

	page := pagination.Page[fingerprint.Evidence]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}
