package intelligence

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
	"ai-recon-platform/internal/domain/intelligence"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/repository/sqlerr"
)

// PostgresRepository implements every interface in this package,
// mirroring internal/repository/investigation.PostgresRepository's shape
// exactly — it depends on database.Executor so the same code works
// standalone or inside a transaction.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var (
	_ RecordRepository        = (*PostgresRepository)(nil)
	_ VulnerabilityRepository = (*PostgresRepository)(nil)
	_ RiskRepository          = (*PostgresRepository)(nil)
	_ EventRepository         = (*PostgresRepository)(nil)
	_ CriticalityRepository   = (*PostgresRepository)(nil)
	_ CacheRepository         = (*PostgresRepository)(nil)
)

func now() time.Time { return time.Now().UTC() }

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

func timePtr(v pgtype.Timestamptz) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
}

func timeParam(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// encodeOffset/decodeOffset implement risk-history pagination's numeric
// offset cursor — independent copies of internal/repository/
// investigation's identically-purposed helpers (risk_scores is ordered
// by calculated_at, not guaranteed unique, the same reason
// timeline_events uses an offset cursor instead of the keyset (created_
// at, id) cursor every other listing in this project uses).
func encodeOffset(n int) string {
	return fmt.Sprintf("o%d", n)
}

func decodeOffset(cursor string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(cursor, "o%d", &n); err != nil {
		return 0, fmt.Errorf("invalid risk history cursor: %w", err)
	}
	return n, nil
}

func joinAnd(conditions []string) string {
	out := conditions[0]
	for _, c := range conditions[1:] {
		out += " AND " + c
	}
	return out
}

// ---------------------------------------------------------------------
// intelligence_records
// ---------------------------------------------------------------------

const recordColumns = `
	id, target_id, indicator_type, indicator_value, provider_id, provider_version, source_type,
	category, verdict, confidence, first_seen, last_seen, expiration, retrieved_at,
	source_reference, normalized_data, tags, created_at, updated_at`

func scanRecord(row pgx.Row) (intelligence.Record, error) {
	var (
		r                   intelligence.Record
		firstSeen, lastSeen pgtype.Timestamptz
		expiration          pgtype.Timestamptz
	)
	err := row.Scan(
		&r.ID, &r.TargetID, &r.IndicatorType, &r.IndicatorValue, &r.ProviderID, &r.ProviderVersion, &r.SourceType,
		&r.Category, &r.Verdict, &r.Confidence, &firstSeen, &lastSeen, &expiration, &r.RetrievedAt,
		&r.SourceReference, &r.NormalizedData, &r.Tags, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return intelligence.Record{}, err
	}
	if firstSeen.Valid {
		r.FirstSeen = firstSeen.Time
	}
	if lastSeen.Valid {
		r.LastSeen = lastSeen.Time
	}
	r.Expiration = timePtr(expiration)
	return r, nil
}

// UpsertRecord implements RecordRepository.
func (r *PostgresRepository) UpsertRecord(ctx context.Context, rec intelligence.Record) (intelligence.Record, bool, error) {
	if rec.RetrievedAt.IsZero() {
		rec.RetrievedAt = now()
	}
	if rec.NormalizedData == nil {
		rec.NormalizedData = map[string]any{}
	}
	if rec.Tags == nil {
		rec.Tags = []string{}
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO intelligence_records (
			target_id, indicator_type, indicator_value, provider_id, provider_version, source_type,
			category, verdict, confidence, first_seen, last_seen, expiration, retrieved_at,
			source_reference, normalized_data, tags
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (target_id, provider_id, indicator_type, indicator_value, verdict, confidence, source_reference)
		DO UPDATE SET
			first_seen = LEAST(COALESCE(intelligence_records.first_seen, EXCLUDED.first_seen), COALESCE(EXCLUDED.first_seen, intelligence_records.first_seen)),
			last_seen = GREATEST(COALESCE(intelligence_records.last_seen, EXCLUDED.last_seen), COALESCE(EXCLUDED.last_seen, intelligence_records.last_seen)),
			expiration = EXCLUDED.expiration,
			retrieved_at = EXCLUDED.retrieved_at,
			normalized_data = EXCLUDED.normalized_data,
			tags = EXCLUDED.tags,
			updated_at = now()
		RETURNING `+recordColumns+`, (xmax = 0) AS inserted`,
		rec.TargetID, rec.IndicatorType, rec.IndicatorValue, rec.ProviderID, rec.ProviderVersion, rec.SourceType,
		rec.Category, rec.Verdict, rec.Confidence, timeParam(nz(rec.FirstSeen)), timeParam(nz(rec.LastSeen)), timeParam(rec.Expiration), rec.RetrievedAt,
		rec.SourceReference, rec.NormalizedData, rec.Tags,
	)

	var (
		result  intelligence.Record
		created bool
		fs, ls  pgtype.Timestamptz
		exp     pgtype.Timestamptz
	)
	err := row.Scan(
		&result.ID, &result.TargetID, &result.IndicatorType, &result.IndicatorValue, &result.ProviderID, &result.ProviderVersion, &result.SourceType,
		&result.Category, &result.Verdict, &result.Confidence, &fs, &ls, &exp, &result.RetrievedAt,
		&result.SourceReference, &result.NormalizedData, &result.Tags, &result.CreatedAt, &result.UpdatedAt,
		&created,
	)
	if err != nil {
		return intelligence.Record{}, false, sqlerr.Translate(err, "upserting intelligence record")
	}
	if fs.Valid {
		result.FirstSeen = fs.Time
	}
	if ls.Valid {
		result.LastSeen = ls.Time
	}
	result.Expiration = timePtr(exp)
	return result, created, nil
}

func nz(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ListRecords implements RecordRepository.
func (r *PostgresRepository) ListRecords(ctx context.Context, filter RecordListFilter) (pagination.Page[intelligence.Record], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[intelligence.Record]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.IndicatorType != "" {
		add("indicator_type = $%d", filter.IndicatorType)
	}
	if filter.IndicatorValue != "" {
		add("indicator_value = $%d", filter.IndicatorValue)
	}
	if filter.ProviderID != "" {
		add("provider_id = $%d", filter.ProviderID)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM intelligence_records WHERE %s ORDER BY created_at, id LIMIT $%d`,
		recordColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[intelligence.Record]{}, sqlerr.Translate(err, "listing intelligence records")
	}
	defer rows.Close()

	var items []intelligence.Record
	for rows.Next() {
		rec, scanErr := scanRecord(rows)
		if scanErr != nil {
			return pagination.Page[intelligence.Record]{}, sqlerr.Translate(scanErr, "scanning intelligence record row")
		}
		items = append(items, rec)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[intelligence.Record]{}, sqlerr.Translate(err, "iterating intelligence records")
	}

	page := pagination.Page[intelligence.Record]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

// ListRecordsByIndicator implements RecordRepository.
func (r *PostgresRepository) ListRecordsByIndicator(ctx context.Context, targetID uuid.UUID, indicatorType intelligence.IndicatorType, indicatorValue string) ([]intelligence.Record, error) {
	rows, err := r.db.Query(ctx, `SELECT `+recordColumns+` FROM intelligence_records
		WHERE target_id = $1 AND indicator_type = $2 AND indicator_value = $3
		ORDER BY created_at, id`, targetID, indicatorType, indicatorValue)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing intelligence records by indicator")
	}
	defer rows.Close()

	var out []intelligence.Record
	for rows.Next() {
		rec, scanErr := scanRecord(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning intelligence record row")
		}
		out = append(out, rec)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating intelligence records")
}

// ---------------------------------------------------------------------
// vulnerability_records / vulnerability_matches
// ---------------------------------------------------------------------

const vulnColumns = `id, identifier, title, description, severity, affected_product, version_constraints, "references", published_at, modified_at, created_at, updated_at`

func scanVuln(row pgx.Row) (intelligence.VulnerabilityRecord, error) {
	var (
		v                       intelligence.VulnerabilityRecord
		publishedAt, modifiedAt pgtype.Timestamptz
	)
	err := row.Scan(&v.ID, &v.Identifier, &v.Title, &v.Description, &v.Severity, &v.AffectedProduct,
		&v.VersionConstraints, &v.References, &publishedAt, &modifiedAt, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		return intelligence.VulnerabilityRecord{}, err
	}
	v.PublishedAt = timePtr(publishedAt)
	v.ModifiedAt = timePtr(modifiedAt)
	return v, nil
}

// UpsertVulnerabilityRecord implements VulnerabilityRepository.
func (r *PostgresRepository) UpsertVulnerabilityRecord(ctx context.Context, v intelligence.VulnerabilityRecord) (intelligence.VulnerabilityRecord, bool, error) {
	if v.VersionConstraints == nil {
		v.VersionConstraints = []string{}
	}
	if v.References == nil {
		v.References = []string{}
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO vulnerability_records (identifier, title, description, severity, affected_product, version_constraints, "references", published_at, modified_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (identifier) DO UPDATE SET
			title = EXCLUDED.title, description = EXCLUDED.description, severity = EXCLUDED.severity,
			affected_product = EXCLUDED.affected_product, version_constraints = EXCLUDED.version_constraints,
			"references" = EXCLUDED."references", published_at = EXCLUDED.published_at, modified_at = EXCLUDED.modified_at,
			updated_at = now()
		RETURNING `+vulnColumns+`, (xmax = 0) AS inserted`,
		v.Identifier, v.Title, v.Description, v.Severity, v.AffectedProduct, v.VersionConstraints, v.References,
		timeParam(v.PublishedAt), timeParam(v.ModifiedAt))

	var (
		result                  intelligence.VulnerabilityRecord
		created                 bool
		publishedAt, modifiedAt pgtype.Timestamptz
	)
	err := row.Scan(&result.ID, &result.Identifier, &result.Title, &result.Description, &result.Severity, &result.AffectedProduct,
		&result.VersionConstraints, &result.References, &publishedAt, &modifiedAt, &result.CreatedAt, &result.UpdatedAt, &created)
	if err != nil {
		return intelligence.VulnerabilityRecord{}, false, sqlerr.Translate(err, "upserting vulnerability record")
	}
	result.PublishedAt = timePtr(publishedAt)
	result.ModifiedAt = timePtr(modifiedAt)
	return result, created, nil
}

// GetVulnerabilityByIdentifier implements VulnerabilityRepository.
func (r *PostgresRepository) GetVulnerabilityByIdentifier(ctx context.Context, identifier string) (intelligence.VulnerabilityRecord, error) {
	row := r.db.QueryRow(ctx, `SELECT `+vulnColumns+` FROM vulnerability_records WHERE identifier = $1`, identifier)
	v, err := scanVuln(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return intelligence.VulnerabilityRecord{}, apperrors.NewNotFound("vulnerability record not found", err)
		}
		return intelligence.VulnerabilityRecord{}, sqlerr.Translate(err, "fetching vulnerability record")
	}
	return v, nil
}

// ListVulnerabilityRecords implements VulnerabilityRepository.
func (r *PostgresRepository) ListVulnerabilityRecords(ctx context.Context, filter VulnerabilityListFilter) (pagination.Page[intelligence.VulnerabilityRecord], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[intelligence.VulnerabilityRecord]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	if filter.AffectedProduct != "" {
		args = append(args, filter.AffectedProduct)
		conditions = append(conditions, fmt.Sprintf("affected_product = $%d", len(args)))
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM vulnerability_records WHERE %s ORDER BY created_at, id LIMIT $%d`, vulnColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[intelligence.VulnerabilityRecord]{}, sqlerr.Translate(err, "listing vulnerability records")
	}
	defer rows.Close()

	var items []intelligence.VulnerabilityRecord
	for rows.Next() {
		v, scanErr := scanVuln(rows)
		if scanErr != nil {
			return pagination.Page[intelligence.VulnerabilityRecord]{}, sqlerr.Translate(scanErr, "scanning vulnerability record row")
		}
		items = append(items, v)
	}
	page := pagination.Page[intelligence.VulnerabilityRecord]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating vulnerability records")
}

const matchColumns = `id, target_id, asset_id, finding_id, vulnerability_id, affected_component, observed_product, observed_version, match_status, confidence, evidence, matching_rule, created_at, updated_at`

func scanMatch(row pgx.Row) (intelligence.VulnerabilityMatch, error) {
	var (
		m         intelligence.VulnerabilityMatch
		findingID pgtype.UUID
	)
	err := row.Scan(&m.ID, &m.TargetID, &m.AssetID, &findingID, &m.VulnerabilityID, &m.AffectedComponent,
		&m.ObservedProduct, &m.ObservedVersion, &m.MatchStatus, &m.Confidence, &m.Evidence, &m.MatchingRule, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return intelligence.VulnerabilityMatch{}, err
	}
	m.FindingID = uuidPtr(findingID)
	return m, nil
}

// UpsertVulnerabilityMatch implements VulnerabilityRepository.
func (r *PostgresRepository) UpsertVulnerabilityMatch(ctx context.Context, m intelligence.VulnerabilityMatch) (intelligence.VulnerabilityMatch, bool, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO vulnerability_matches (target_id, asset_id, finding_id, vulnerability_id, affected_component, observed_product, observed_version, match_status, confidence, evidence, matching_rule)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (asset_id, vulnerability_id, observed_version) DO UPDATE SET
			finding_id = EXCLUDED.finding_id, affected_component = EXCLUDED.affected_component,
			match_status = EXCLUDED.match_status, confidence = EXCLUDED.confidence,
			evidence = EXCLUDED.evidence, matching_rule = EXCLUDED.matching_rule, updated_at = now()
		RETURNING `+matchColumns+`, (xmax = 0) AS inserted`,
		m.TargetID, m.AssetID, uuidParam(m.FindingID), m.VulnerabilityID, m.AffectedComponent, m.ObservedProduct,
		m.ObservedVersion, m.MatchStatus, m.Confidence, m.Evidence, m.MatchingRule)

	var (
		result    intelligence.VulnerabilityMatch
		created   bool
		findingID pgtype.UUID
	)
	err := row.Scan(&result.ID, &result.TargetID, &result.AssetID, &findingID, &result.VulnerabilityID, &result.AffectedComponent,
		&result.ObservedProduct, &result.ObservedVersion, &result.MatchStatus, &result.Confidence, &result.Evidence, &result.MatchingRule,
		&result.CreatedAt, &result.UpdatedAt, &created)
	if err != nil {
		return intelligence.VulnerabilityMatch{}, false, sqlerr.Translate(err, "upserting vulnerability match")
	}
	result.FindingID = uuidPtr(findingID)
	return result, created, nil
}

// ListVulnerabilityMatches implements VulnerabilityRepository.
func (r *PostgresRepository) ListVulnerabilityMatches(ctx context.Context, filter MatchListFilter) (pagination.Page[intelligence.VulnerabilityMatch], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[intelligence.VulnerabilityMatch]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.AssetID != uuid.Nil {
		add("asset_id = $%d", filter.AssetID)
	}
	if filter.FindingID != nil {
		add("finding_id = $%d", *filter.FindingID)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM vulnerability_matches WHERE %s ORDER BY created_at, id LIMIT $%d`, matchColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[intelligence.VulnerabilityMatch]{}, sqlerr.Translate(err, "listing vulnerability matches")
	}
	defer rows.Close()

	var items []intelligence.VulnerabilityMatch
	for rows.Next() {
		m, scanErr := scanMatch(rows)
		if scanErr != nil {
			return pagination.Page[intelligence.VulnerabilityMatch]{}, sqlerr.Translate(scanErr, "scanning vulnerability match row")
		}
		items = append(items, m)
	}
	page := pagination.Page[intelligence.VulnerabilityMatch]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating vulnerability matches")
}

// ---------------------------------------------------------------------
// risk_scores
// ---------------------------------------------------------------------

const riskColumns = `id, target_id, entity_type, entity_id, score, severity, confidence, model_version, factors, explanation, calculated_at, created_at`

func scanRisk(row pgx.Row) (intelligence.RiskScore, error) {
	var (
		rs         intelligence.RiskScore
		factorsRaw []byte
	)
	err := row.Scan(&rs.ID, &rs.TargetID, &rs.EntityType, &rs.EntityID, &rs.Score, &rs.Severity, &rs.Confidence,
		&rs.ModelVersion, &factorsRaw, &rs.Explanation, &rs.CalculatedAt, &rs.CreatedAt)
	if err != nil {
		return intelligence.RiskScore{}, err
	}
	if len(factorsRaw) > 0 {
		if err := json.Unmarshal(factorsRaw, &rs.Factors); err != nil {
			return intelligence.RiskScore{}, fmt.Errorf("decoding risk factors: %w", err)
		}
	}
	return rs, nil
}

// CreateRiskScore implements RiskRepository.
func (r *PostgresRepository) CreateRiskScore(ctx context.Context, rs intelligence.RiskScore) (intelligence.RiskScore, error) {
	if rs.CalculatedAt.IsZero() {
		rs.CalculatedAt = now()
	}
	if rs.Factors == nil {
		rs.Factors = []intelligence.RiskFactor{}
	}
	factorsJSON, err := json.Marshal(rs.Factors)
	if err != nil {
		return intelligence.RiskScore{}, fmt.Errorf("encoding risk factors: %w", err)
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO risk_scores (target_id, entity_type, entity_id, score, severity, confidence, model_version, factors, explanation, calculated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING `+riskColumns,
		rs.TargetID, rs.EntityType, rs.EntityID, rs.Score, rs.Severity, rs.Confidence, rs.ModelVersion, factorsJSON, rs.Explanation, rs.CalculatedAt)

	result, err := scanRisk(row)
	if err != nil {
		return intelligence.RiskScore{}, sqlerr.Translate(err, "creating risk score")
	}
	return result, nil
}

// GetLatestRiskScore implements RiskRepository.
func (r *PostgresRepository) GetLatestRiskScore(ctx context.Context, entityType intelligence.EntityType, entityID uuid.UUID) (intelligence.RiskScore, error) {
	row := r.db.QueryRow(ctx, `SELECT `+riskColumns+` FROM risk_scores
		WHERE entity_type = $1 AND entity_id = $2 ORDER BY calculated_at DESC, id DESC LIMIT 1`, entityType, entityID)
	rs, err := scanRisk(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return intelligence.RiskScore{}, apperrors.NewNotFound("no risk score has been calculated yet", err)
		}
		return intelligence.RiskScore{}, sqlerr.Translate(err, "fetching latest risk score")
	}
	return rs, nil
}

// ListRiskHistory implements RiskRepository.
func (r *PostgresRepository) ListRiskHistory(ctx context.Context, entityType intelligence.EntityType, entityID uuid.UUID, params pagination.Params) (pagination.Page[intelligence.RiskScore], error) {
	limit := params.ResolveLimit()
	// Risk history is ordered newest-first (phase10.md §46's "risk over
	// time"), using a numeric offset cursor — the same "ordering isn't by
	// (created_at, id) ascending" exception
	// internal/repository/investigation.ListTimeline documents for the
	// identical reason.
	offset := 0
	if params.Cursor != "" {
		var err error
		offset, err = decodeOffset(params.Cursor)
		if err != nil {
			return pagination.Page[intelligence.RiskScore]{}, apperrors.NewValidation("invalid pagination cursor", err)
		}
	}

	rows, err := r.db.Query(ctx, `SELECT `+riskColumns+` FROM risk_scores
		WHERE entity_type = $1 AND entity_id = $2
		ORDER BY calculated_at DESC, id DESC
		LIMIT $3 OFFSET $4`, entityType, entityID, limit+1, offset)
	if err != nil {
		return pagination.Page[intelligence.RiskScore]{}, sqlerr.Translate(err, "listing risk history")
	}
	defer rows.Close()

	var items []intelligence.RiskScore
	for rows.Next() {
		rs, scanErr := scanRisk(rows)
		if scanErr != nil {
			return pagination.Page[intelligence.RiskScore]{}, sqlerr.Translate(scanErr, "scanning risk score row")
		}
		items = append(items, rs)
	}

	page := pagination.Page[intelligence.RiskScore]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = encodeOffset(offset + limit)
	}
	return page, sqlerr.Translate(rows.Err(), "iterating risk history")
}

// ---------------------------------------------------------------------
// enrichment_events
// ---------------------------------------------------------------------

const eventColumns = `id, target_id, indicator_type, indicator_value, event_type, source, source_id, "timestamp", previous_value, new_value, confidence, created_at`

func scanEvent(row pgx.Row) (intelligence.EnrichmentEvent, error) {
	var e intelligence.EnrichmentEvent
	err := row.Scan(&e.ID, &e.TargetID, &e.IndicatorType, &e.IndicatorValue, &e.EventType, &e.Source, &e.SourceID,
		&e.Timestamp, &e.PreviousValue, &e.NewValue, &e.Confidence, &e.CreatedAt)
	return e, err
}

// RecordEvent implements EventRepository.
func (r *PostgresRepository) RecordEvent(ctx context.Context, e intelligence.EnrichmentEvent) (intelligence.EnrichmentEvent, error) {
	if e.Timestamp.IsZero() {
		e.Timestamp = now()
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO enrichment_events (target_id, indicator_type, indicator_value, event_type, source, source_id, "timestamp", previous_value, new_value, confidence)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING `+eventColumns,
		e.TargetID, e.IndicatorType, e.IndicatorValue, e.EventType, e.Source, e.SourceID, e.Timestamp, e.PreviousValue, e.NewValue, e.Confidence)
	result, err := scanEvent(row)
	if err != nil {
		return intelligence.EnrichmentEvent{}, sqlerr.Translate(err, "recording enrichment event")
	}
	return result, nil
}

// ListEvents implements EventRepository.
func (r *PostgresRepository) ListEvents(ctx context.Context, filter EventListFilter) (pagination.Page[intelligence.EnrichmentEvent], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[intelligence.EnrichmentEvent]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.IndicatorType != "" {
		add("indicator_type = $%d", filter.IndicatorType)
	}
	if filter.IndicatorValue != "" {
		add("indicator_value = $%d", filter.IndicatorValue)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM enrichment_events WHERE %s ORDER BY created_at, id LIMIT $%d`, eventColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[intelligence.EnrichmentEvent]{}, sqlerr.Translate(err, "listing enrichment events")
	}
	defer rows.Close()

	var items []intelligence.EnrichmentEvent
	for rows.Next() {
		e, scanErr := scanEvent(rows)
		if scanErr != nil {
			return pagination.Page[intelligence.EnrichmentEvent]{}, sqlerr.Translate(scanErr, "scanning enrichment event row")
		}
		items = append(items, e)
	}
	page := pagination.Page[intelligence.EnrichmentEvent]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating enrichment events")
}

// ---------------------------------------------------------------------
// asset_criticality
// ---------------------------------------------------------------------

// SetCriticality implements CriticalityRepository.
func (r *PostgresRepository) SetCriticality(ctx context.Context, a intelligence.AssetCriticality) (intelligence.AssetCriticality, error) {
	if a.SetAt.IsZero() {
		a.SetAt = now()
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO asset_criticality (asset_id, target_id, criticality, set_by, set_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (asset_id) DO UPDATE SET
			criticality = EXCLUDED.criticality, set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at, updated_at = now()
		RETURNING asset_id, target_id, criticality, set_by, set_at, updated_at`,
		a.AssetID, a.TargetID, a.Criticality, a.SetBy, a.SetAt)

	var result intelligence.AssetCriticality
	if err := row.Scan(&result.AssetID, &result.TargetID, &result.Criticality, &result.SetBy, &result.SetAt, &result.UpdatedAt); err != nil {
		return intelligence.AssetCriticality{}, sqlerr.Translate(err, "setting asset criticality")
	}
	return result, nil
}

// GetCriticality implements CriticalityRepository.
func (r *PostgresRepository) GetCriticality(ctx context.Context, assetID uuid.UUID) (intelligence.AssetCriticality, bool, error) {
	row := r.db.QueryRow(ctx, `SELECT asset_id, target_id, criticality, set_by, set_at, updated_at FROM asset_criticality WHERE asset_id = $1`, assetID)
	var result intelligence.AssetCriticality
	err := row.Scan(&result.AssetID, &result.TargetID, &result.Criticality, &result.SetBy, &result.SetAt, &result.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return intelligence.AssetCriticality{}, false, nil
		}
		return intelligence.AssetCriticality{}, false, sqlerr.Translate(err, "fetching asset criticality")
	}
	return result, true, nil
}

// ---------------------------------------------------------------------
// intelligence_cache
// ---------------------------------------------------------------------

// GetCacheEntry implements CacheRepository.
func (r *PostgresRepository) GetCacheEntry(ctx context.Context, providerID string, indicatorType, indicatorValue string) ([]byte, *time.Time, bool, error) {
	row := r.db.QueryRow(ctx, `SELECT records, expires_at FROM intelligence_cache WHERE provider_id = $1 AND indicator_type = $2 AND indicator_value = $3`,
		providerID, indicatorType, indicatorValue)
	var (
		data      []byte
		expiresAt pgtype.Timestamptz
	)
	if err := row.Scan(&data, &expiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, false, nil
		}
		return nil, nil, false, sqlerr.Translate(err, "fetching cache entry")
	}
	return data, timePtr(expiresAt), true, nil
}

// SetCacheEntry implements CacheRepository.
func (r *PostgresRepository) SetCacheEntry(ctx context.Context, providerID string, indicatorType, indicatorValue string, data []byte, expiresAt *time.Time) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO intelligence_cache (provider_id, indicator_type, indicator_value, records, cached_at, expires_at)
		VALUES ($1,$2,$3,$4, now(), $5)
		ON CONFLICT (provider_id, indicator_type, indicator_value) DO UPDATE SET
			records = EXCLUDED.records, cached_at = now(), expires_at = EXCLUDED.expires_at`,
		providerID, indicatorType, indicatorValue, data, timeParam(expiresAt))
	return sqlerr.Translate(err, "writing cache entry")
}

// InvalidateCacheEntry implements CacheRepository.
func (r *PostgresRepository) InvalidateCacheEntry(ctx context.Context, providerID string, indicatorType, indicatorValue string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM intelligence_cache WHERE provider_id = $1 AND indicator_type = $2 AND indicator_value = $3`,
		providerID, indicatorType, indicatorValue)
	return sqlerr.Translate(err, "invalidating cache entry")
}
