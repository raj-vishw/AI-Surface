package asset

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/domain/asset"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/repository/sqlerr"
)

// PostgresRepository implements both Repository and EvidenceRepository. It
// depends on database.Executor rather than *database.Pool directly so the
// same code works both standalone and inside a transaction (see
// database.Pool.WithTx) — asset.Service uses this to upsert an asset and
// record its evidence atomically.
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

const assetColumns = `
	id, target_id, organization_id, type, hostname, ip::text, port, protocol, url,
	technology, provider, model, environment, source, identity_key,
	first_seen, last_seen, status, confidence, metadata, created_at, updated_at`

func scanAsset(row pgx.Row) (asset.Asset, error) {
	var (
		a              asset.Asset
		organizationID pgtype.UUID
		hostname       pgtype.Text
		ip             pgtype.Text
		port           pgtype.Int4
		protocol       pgtype.Text
		assetURL       pgtype.Text
		technology     pgtype.Text
		provider       pgtype.Text
		model          pgtype.Text
		environment    pgtype.Text
		confidence     float64
	)
	err := row.Scan(
		&a.ID, &a.TargetID, &organizationID, &a.Type, &hostname, &ip, &port, &protocol, &assetURL,
		&technology, &provider, &model, &environment, &a.Source, &a.IdentityKey,
		&a.FirstSeen, &a.LastSeen, &a.Status, &confidence, &a.Metadata, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return asset.Asset{}, err
	}

	a.OrganizationID = uuidPtr(organizationID)
	a.Hostname = textPtr(hostname)
	a.IP = textPtr(ip)
	a.Port = int4Ptr(port)
	a.Protocol = textPtr(protocol)
	a.URL = textPtr(assetURL)
	a.Technology = textPtr(technology)
	a.Provider = textPtr(provider)
	a.Model = textPtr(model)
	a.Environment = textPtr(environment)
	a.Confidence = asset.Confidence(confidence)
	return a, nil
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

func textPtr(v pgtype.Text) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

func textParam(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

func int4Ptr(v pgtype.Int4) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int32)
	return &n
}

func int4Param(n *int) pgtype.Int4 {
	if n == nil {
		return pgtype.Int4{Valid: false}
	}
	// asset.Asset.Validate rejects ports outside 1-65535 before this is
	// ever called, so the narrowing to int32 is always in range.
	return pgtype.Int4{Int32: int32(*n), Valid: true} //nolint:gosec // bounds-checked by domain validation before persistence
}

// inetParam converts an optional IP-address string into the netip.Prefix
// pgx uses to encode PostgreSQL's inet type — a /32 (IPv4) or /128 (IPv6)
// host prefix, i.e. exactly the address with no subnet.
func inetParam(ip *string) (*netip.Prefix, error) {
	if ip == nil {
		return nil, nil
	}
	addr, err := netip.ParseAddr(*ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %q: %w", *ip, err)
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	return &prefix, nil
}

// Create implements Repository.
func (r *PostgresRepository) Create(ctx context.Context, a asset.Asset) (asset.Asset, error) {
	ip, err := inetParam(a.IP)
	if err != nil {
		return asset.Asset{}, apperrors.NewValidation(err.Error(), err)
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	if a.Status == "" {
		a.Status = asset.StatusDiscovered
	}
	if a.Metadata == nil {
		a.Metadata = map[string]any{}
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO assets (
			target_id, organization_id, type, hostname, ip, port, protocol, url,
			technology, provider, model, environment, source, identity_key,
			first_seen, last_seen, status, confidence, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
		RETURNING `+assetColumns,
		a.TargetID, uuidParam(a.OrganizationID), a.Type, textParam(a.Hostname), ip, int4Param(a.Port),
		textParam(a.Protocol), textParam(a.URL), textParam(a.Technology), textParam(a.Provider),
		textParam(a.Model), textParam(a.Environment), a.Source, a.IdentityKey,
		a.FirstSeen, a.LastSeen, a.Status, float64(a.Confidence), a.Metadata,
	)
	created, err := scanAsset(row)
	if err != nil {
		return asset.Asset{}, sqlerr.Translate(err, "creating asset")
	}
	return created, nil
}

// GetByID implements Repository.
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (asset.Asset, error) {
	row := r.db.QueryRow(ctx, `SELECT `+assetColumns+` FROM assets WHERE id = $1`, id)
	a, err := scanAsset(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return asset.Asset{}, apperrors.NewNotFound("asset not found", err)
		}
		return asset.Asset{}, sqlerr.Translate(err, "fetching asset")
	}
	return a, nil
}

// GetByIdentity implements Repository.
func (r *PostgresRepository) GetByIdentity(ctx context.Context, targetID uuid.UUID, identityKey string) (asset.Asset, error) {
	row := r.db.QueryRow(ctx, `SELECT `+assetColumns+` FROM assets WHERE target_id = $1 AND identity_key = $2`, targetID, identityKey)
	a, err := scanAsset(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return asset.Asset{}, apperrors.NewNotFound("asset not found", err)
		}
		return asset.Asset{}, sqlerr.Translate(err, "fetching asset")
	}
	return a, nil
}

// Update implements Repository.
func (r *PostgresRepository) Update(ctx context.Context, a asset.Asset) (asset.Asset, error) {
	ip, err := inetParam(a.IP)
	if err != nil {
		return asset.Asset{}, apperrors.NewValidation(err.Error(), err)
	}

	row := r.db.QueryRow(ctx, `
		UPDATE assets SET
			organization_id = $2, hostname = $3, ip = $4, port = $5, protocol = $6, url = $7,
			technology = $8, provider = $9, model = $10, environment = $11,
			last_seen = $12, status = $13, confidence = $14, metadata = $15, updated_at = now()
		WHERE id = $1
		RETURNING `+assetColumns,
		a.ID, uuidParam(a.OrganizationID), textParam(a.Hostname), ip, int4Param(a.Port),
		textParam(a.Protocol), textParam(a.URL), textParam(a.Technology), textParam(a.Provider),
		textParam(a.Model), textParam(a.Environment), a.LastSeen, a.Status, float64(a.Confidence), a.Metadata,
	)
	updated, err := scanAsset(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return asset.Asset{}, apperrors.NewNotFound("asset not found", err)
		}
		return asset.Asset{}, sqlerr.Translate(err, "updating asset")
	}
	return updated, nil
}

// Upsert implements Repository. See the interface doc comment for the
// merge semantics; ON CONFLICT ... DO UPDATE makes the whole operation a
// single atomic, race-free statement — safe for concurrent callers
// observing the same identity, including out of timestamp order (see
// TestAssetPersistence_ConcurrentUpsertSameIdentity).
func (r *PostgresRepository) Upsert(ctx context.Context, a asset.Asset) (asset.Asset, bool, error) {
	ip, err := inetParam(a.IP)
	if err != nil {
		return asset.Asset{}, false, apperrors.NewValidation(err.Error(), err)
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	if a.Status == "" {
		a.Status = asset.StatusDiscovered
	}
	if a.Metadata == nil {
		a.Metadata = map[string]any{}
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO assets (
			target_id, organization_id, type, hostname, ip, port, protocol, url,
			technology, provider, model, environment, source, identity_key,
			first_seen, last_seen, status, confidence, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
		ON CONFLICT (target_id, identity_key) DO UPDATE SET
			organization_id = COALESCE(assets.organization_id, EXCLUDED.organization_id),
			hostname         = COALESCE(EXCLUDED.hostname, assets.hostname),
			ip               = COALESCE(EXCLUDED.ip, assets.ip),
			port             = COALESCE(EXCLUDED.port, assets.port),
			protocol         = COALESCE(EXCLUDED.protocol, assets.protocol),
			url              = COALESCE(EXCLUDED.url, assets.url),
			technology       = COALESCE(EXCLUDED.technology, assets.technology),
			provider         = COALESCE(EXCLUDED.provider, assets.provider),
			model            = COALESCE(EXCLUDED.model, assets.model),
			environment      = COALESCE(EXCLUDED.environment, assets.environment),
			first_seen       = LEAST(assets.first_seen, EXCLUDED.first_seen),
			last_seen        = GREATEST(assets.last_seen, EXCLUDED.last_seen),
			confidence       = GREATEST(assets.confidence, EXCLUDED.confidence),
			metadata         = assets.metadata || EXCLUDED.metadata,
			updated_at       = now()
		RETURNING `+assetColumns+`, (xmax = 0) AS inserted`,
		a.TargetID, uuidParam(a.OrganizationID), a.Type, textParam(a.Hostname), ip, int4Param(a.Port),
		textParam(a.Protocol), textParam(a.URL), textParam(a.Technology), textParam(a.Provider),
		textParam(a.Model), textParam(a.Environment), a.Source, a.IdentityKey,
		a.FirstSeen, a.LastSeen, a.Status, float64(a.Confidence), a.Metadata,
	)

	result, created, err := scanUpsertedAsset(row)
	if err != nil {
		return asset.Asset{}, false, sqlerr.Translate(err, "upserting asset")
	}
	return result, created, nil
}

// scanUpsertedAsset scans an asset row plus the trailing "inserted" column
// produced by Upsert's `(xmax = 0) AS inserted` trick: xmax is the deleting
// transaction ID slot, which PostgreSQL leaves as 0 on a freshly inserted
// row and sets to the current transaction on an UPDATE (including the
// UPDATE half of ON CONFLICT DO UPDATE) — so "xmax = 0" reliably tells INSERT
// and UPDATE apart in a single RETURNING clause without a second query.
func scanUpsertedAsset(row pgx.Row) (asset.Asset, bool, error) {
	var (
		a              asset.Asset
		organizationID pgtype.UUID
		hostname       pgtype.Text
		ip             pgtype.Text
		port           pgtype.Int4
		protocol       pgtype.Text
		assetURL       pgtype.Text
		technology     pgtype.Text
		provider       pgtype.Text
		model          pgtype.Text
		environment    pgtype.Text
		confidence     float64
		inserted       bool
	)
	err := row.Scan(
		&a.ID, &a.TargetID, &organizationID, &a.Type, &hostname, &ip, &port, &protocol, &assetURL,
		&technology, &provider, &model, &environment, &a.Source, &a.IdentityKey,
		&a.FirstSeen, &a.LastSeen, &a.Status, &confidence, &a.Metadata, &a.CreatedAt, &a.UpdatedAt,
		&inserted,
	)
	if err != nil {
		return asset.Asset{}, false, err
	}
	a.OrganizationID = uuidPtr(organizationID)
	a.Hostname = textPtr(hostname)
	a.IP = textPtr(ip)
	a.Port = int4Ptr(port)
	a.Protocol = textPtr(protocol)
	a.URL = textPtr(assetURL)
	a.Technology = textPtr(technology)
	a.Provider = textPtr(provider)
	a.Model = textPtr(model)
	a.Environment = textPtr(environment)
	a.Confidence = asset.Confidence(confidence)
	return a, inserted, nil
}

// UpdateStatus implements Repository.
func (r *PostgresRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status asset.Status) (asset.Asset, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE assets SET status = $2, updated_at = now() WHERE id = $1
		RETURNING `+assetColumns,
		id, status,
	)
	updated, err := scanAsset(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return asset.Asset{}, apperrors.NewNotFound("asset not found", err)
		}
		return asset.Asset{}, sqlerr.Translate(err, "updating asset status")
	}
	return updated, nil
}

// Retire implements Repository.
func (r *PostgresRepository) Retire(ctx context.Context, id uuid.UUID) (asset.Asset, error) {
	return r.UpdateStatus(ctx, id, asset.StatusRetired)
}

// List implements Repository.
func (r *PostgresRepository) List(ctx context.Context, filter ListFilter) (pagination.Page[asset.Asset], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[asset.Asset]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.OrganizationID != nil {
		add("organization_id = $%d", *filter.OrganizationID)
	}
	if filter.Type != "" {
		add("type = $%d", filter.Type)
	}
	if filter.Hostname != "" {
		add("hostname = $%d", filter.Hostname)
	}
	if filter.IP != "" {
		add("ip = $%d::inet", filter.IP)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if filter.Source != "" {
		add("source = $%d", filter.Source)
	}
	if filter.Provider != "" {
		add("provider = $%d", filter.Provider)
	}
	if filter.Model != "" {
		add("model = $%d", filter.Model)
	}
	if !filter.FirstSeenAfter.IsZero() {
		add("first_seen >= $%d", filter.FirstSeenAfter)
	}
	if !filter.FirstSeenBefore.IsZero() {
		add("first_seen <= $%d", filter.FirstSeenBefore)
	}
	if !filter.LastSeenAfter.IsZero() {
		add("last_seen >= $%d", filter.LastSeenAfter)
	}
	if !filter.LastSeenBefore.IsZero() {
		add("last_seen <= $%d", filter.LastSeenBefore)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, limit+1)
	query := fmt.Sprintf(`
		SELECT %s FROM assets
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, assetColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[asset.Asset]{}, sqlerr.Translate(err, "listing assets")
	}
	defer rows.Close()

	var items []asset.Asset
	for rows.Next() {
		a, scanErr := scanAsset(rows)
		if scanErr != nil {
			return pagination.Page[asset.Asset]{}, sqlerr.Translate(scanErr, "scanning asset row")
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[asset.Asset]{}, sqlerr.Translate(err, "iterating assets")
	}

	page := pagination.Page[asset.Asset]{Items: items}
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

const evidenceColumns = `id, asset_id, source, evidence_type, evidence_data, evidence_fingerprint, confidence, observed_at, created_at`

func scanEvidence(row pgx.Row) (asset.Evidence, error) {
	var (
		e           asset.Evidence
		fingerprint string
		confidence  float64
	)
	err := row.Scan(&e.ID, &e.AssetID, &e.Source, &e.EvidenceType, &e.EvidenceData, &fingerprint, &confidence, &e.ObservedAt, &e.CreatedAt)
	if err != nil {
		return asset.Evidence{}, err
	}
	e.Fingerprint = fingerprint
	e.Confidence = asset.Confidence(confidence)
	return e, nil
}

// CreateEvidence implements EvidenceRepository. See the interface doc
// comment for the deduplication semantics.
func (r *PostgresRepository) CreateEvidence(ctx context.Context, e asset.Evidence) (asset.Evidence, bool, error) {
	if e.EvidenceData == nil {
		e.EvidenceData = map[string]any{}
	}
	if e.ObservedAt.IsZero() {
		e.ObservedAt = time.Now().UTC()
	}
	fingerprint, err := asset.EvidenceFingerprint(e.EvidenceData)
	if err != nil {
		return asset.Evidence{}, false, apperrors.NewValidation("computing evidence fingerprint", err)
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO asset_evidence (asset_id, source, evidence_type, evidence_data, evidence_fingerprint, confidence, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (asset_id, source, evidence_type, evidence_fingerprint) DO NOTHING
		RETURNING `+evidenceColumns,
		e.AssetID, e.Source, e.EvidenceType, e.EvidenceData, fingerprint, float64(e.Confidence), e.ObservedAt,
	)
	created, err := scanEvidence(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ON CONFLICT DO NOTHING means identical evidence already
			// exists; return the existing row so callers still get a
			// complete Evidence value.
			existing, getErr := r.getEvidenceByFingerprint(ctx, e.AssetID, e.Source, e.EvidenceType, fingerprint)
			if getErr != nil {
				return asset.Evidence{}, false, getErr
			}
			return existing, false, nil
		}
		return asset.Evidence{}, false, sqlerr.Translate(err, "creating asset evidence")
	}
	return created, true, nil
}

func (r *PostgresRepository) getEvidenceByFingerprint(ctx context.Context, assetID uuid.UUID, source string, evidenceType asset.EvidenceType, fingerprint string) (asset.Evidence, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+evidenceColumns+` FROM asset_evidence
		WHERE asset_id = $1 AND source = $2 AND evidence_type = $3 AND evidence_fingerprint = $4`,
		assetID, source, evidenceType, fingerprint,
	)
	e, err := scanEvidence(row)
	if err != nil {
		return asset.Evidence{}, sqlerr.Translate(err, "fetching existing asset evidence")
	}
	return e, nil
}

// ListEvidenceByAsset implements EvidenceRepository.
func (r *PostgresRepository) ListEvidenceByAsset(ctx context.Context, filter EvidenceListFilter) (pagination.Page[asset.Evidence], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[asset.Evidence]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"asset_id = $1"}
	args := []any{filter.AssetID}
	if filter.Source != "" {
		args = append(args, filter.Source)
		conditions = append(conditions, fmt.Sprintf("source = $%d", len(args)))
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`
		SELECT %s FROM asset_evidence
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, evidenceColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[asset.Evidence]{}, sqlerr.Translate(err, "listing asset evidence")
	}
	defer rows.Close()

	var items []asset.Evidence
	for rows.Next() {
		e, scanErr := scanEvidence(rows)
		if scanErr != nil {
			return pagination.Page[asset.Evidence]{}, sqlerr.Translate(scanErr, "scanning asset evidence row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[asset.Evidence]{}, sqlerr.Translate(err, "iterating asset evidence")
	}

	page := pagination.Page[asset.Evidence]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}
