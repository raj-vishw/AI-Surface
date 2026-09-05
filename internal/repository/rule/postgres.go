package rule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/domain/rule"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/repository/sqlerr"
)

// PostgresRepository implements every interface in this package,
// mirroring internal/repository/investigation.PostgresRepository's shape
// exactly.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var (
	_ Repository            = (*PostgresRepository)(nil)
	_ VersionRepository     = (*PostgresRepository)(nil)
	_ MatchRepository       = (*PostgresRepository)(nil)
	_ EvidenceRepository    = (*PostgresRepository)(nil)
	_ AlertRepository       = (*PostgresRepository)(nil)
	_ SuppressionRepository = (*PostgresRepository)(nil)
)

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

func uuidPtr(v pgtype.UUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := uuid.UUID(v.Bytes)
	return &id
}

func joinAnd(conditions []string) string {
	out := conditions[0]
	for _, c := range conditions[1:] {
		out += " AND " + c
	}
	return out
}

// ---------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------

const ruleColumns = `id, target_id, name, description, status, rule_type, severity, confidence, category, tags, "references", documentation_url, created_by, updated_by, created_at, updated_at`

func scanRule(row pgx.Row) (rule.Rule, error) {
	var r rule.Rule
	err := row.Scan(&r.ID, &r.TargetID, &r.Name, &r.Description, &r.Status, &r.RuleType, &r.Severity, &r.Confidence,
		&r.Category, &r.Tags, &r.References, &r.DocumentationURL, &r.CreatedBy, &r.UpdatedBy, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// CreateRule implements Repository.
func (r *PostgresRepository) CreateRule(ctx context.Context, ru rule.Rule) (rule.Rule, error) {
	if ru.Tags == nil {
		ru.Tags = []string{}
	}
	if ru.References == nil {
		ru.References = []string{}
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO rules (target_id, name, description, status, rule_type, severity, confidence, category, tags, "references", documentation_url, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
		RETURNING `+ruleColumns,
		ru.TargetID, ru.Name, ru.Description, ru.Status, ru.RuleType, ru.Severity, ru.Confidence,
		ru.Category, ru.Tags, ru.References, ru.DocumentationURL, ru.CreatedBy)
	result, err := scanRule(row)
	if err != nil {
		return rule.Rule{}, sqlerr.Translate(err, "creating rule")
	}
	return result, nil
}

// GetRuleByID implements Repository.
func (r *PostgresRepository) GetRuleByID(ctx context.Context, id uuid.UUID) (rule.Rule, error) {
	row := r.db.QueryRow(ctx, `SELECT `+ruleColumns+` FROM rules WHERE id = $1`, id)
	result, err := scanRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Rule{}, apperrors.NewNotFound("rule not found", err)
		}
		return rule.Rule{}, sqlerr.Translate(err, "fetching rule")
	}
	return result, nil
}

// GetByName implements Repository.
func (r *PostgresRepository) GetByName(ctx context.Context, targetID uuid.UUID, name string) (rule.Rule, error) {
	row := r.db.QueryRow(ctx, `SELECT `+ruleColumns+` FROM rules WHERE target_id = $1 AND name = $2`, targetID, name)
	result, err := scanRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Rule{}, apperrors.NewNotFound("rule not found", err)
		}
		return rule.Rule{}, sqlerr.Translate(err, "fetching rule by name")
	}
	return result, nil
}

// ListRules implements Repository.
func (r *PostgresRepository) ListRules(ctx context.Context, filter ListFilter) (pagination.Page[rule.Rule], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[rule.Rule]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if filter.RuleType != "" {
		add("rule_type = $%d", filter.RuleType)
	}
	if filter.Category != "" {
		add("category = $%d", filter.Category)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM rules WHERE %s ORDER BY created_at, id LIMIT $%d`, ruleColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[rule.Rule]{}, sqlerr.Translate(err, "listing rules")
	}
	defer rows.Close()

	var items []rule.Rule
	for rows.Next() {
		ru, scanErr := scanRule(rows)
		if scanErr != nil {
			return pagination.Page[rule.Rule]{}, sqlerr.Translate(scanErr, "scanning rule row")
		}
		items = append(items, ru)
	}
	page := pagination.Page[rule.Rule]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating rules")
}

// UpdateMetadata implements Repository.
func (r *PostgresRepository) UpdateMetadata(ctx context.Context, id uuid.UUID, description, category string, tags, references []string, documentationURL, updatedBy string) (rule.Rule, error) {
	if tags == nil {
		tags = []string{}
	}
	if references == nil {
		references = []string{}
	}
	row := r.db.QueryRow(ctx, `
		UPDATE rules SET description = $2, category = $3, tags = $4, "references" = $5, documentation_url = $6, updated_by = $7, updated_at = now()
		WHERE id = $1 RETURNING `+ruleColumns,
		id, description, category, tags, references, documentationURL, updatedBy)
	result, err := scanRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Rule{}, apperrors.NewNotFound("rule not found", err)
		}
		return rule.Rule{}, sqlerr.Translate(err, "updating rule metadata")
	}
	return result, nil
}

// UpdateRuleStatus implements Repository.
func (r *PostgresRepository) UpdateRuleStatus(ctx context.Context, id uuid.UUID, status rule.Status, updatedBy string) (rule.Rule, error) {
	row := r.db.QueryRow(ctx, `UPDATE rules SET status = $2, updated_by = $3, updated_at = now() WHERE id = $1 RETURNING `+ruleColumns,
		id, status, updatedBy)
	result, err := scanRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Rule{}, apperrors.NewNotFound("rule not found", err)
		}
		return rule.Rule{}, sqlerr.Translate(err, "updating rule status")
	}
	return result, nil
}

// SyncSeverityFromVersion implements Repository.
func (r *PostgresRepository) SyncSeverityFromVersion(ctx context.Context, id uuid.UUID, severity rule.Severity, confidence rule.Confidence, ruleType rule.Type) (rule.Rule, error) {
	row := r.db.QueryRow(ctx, `UPDATE rules SET severity = $2, confidence = $3, rule_type = $4, updated_at = now() WHERE id = $1 RETURNING `+ruleColumns,
		id, severity, confidence, ruleType)
	result, err := scanRule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Rule{}, apperrors.NewNotFound("rule not found", err)
		}
		return rule.Rule{}, sqlerr.Translate(err, "syncing rule severity from version")
	}
	return result, nil
}

// ---------------------------------------------------------------------
// rule_versions
// ---------------------------------------------------------------------

const versionColumns = `id, rule_id, version, definition, definition_hash, enabled, event_schema_version, created_by, created_at, change_description`

func scanVersion(row pgx.Row) (rule.Version, error) {
	var v rule.Version
	err := row.Scan(&v.ID, &v.RuleID, &v.Version, &v.Definition, &v.DefinitionHash, &v.Enabled, &v.EventSchemaVersion, &v.CreatedBy, &v.CreatedAt, &v.ChangeDescription)
	return v, err
}

// CreateVersion implements VersionRepository.
func (r *PostgresRepository) CreateVersion(ctx context.Context, v rule.Version) (rule.Version, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO rule_versions (rule_id, version, definition, definition_hash, enabled, event_schema_version, created_by, change_description)
		VALUES ($1, COALESCE((SELECT MAX(version) FROM rule_versions WHERE rule_id = $1), 0) + 1, $2, $3, $4, $5, $6, $7)
		RETURNING `+versionColumns,
		v.RuleID, v.Definition, v.DefinitionHash, v.Enabled, v.EventSchemaVersion, v.CreatedBy, v.ChangeDescription)
	result, err := scanVersion(row)
	if err != nil {
		return rule.Version{}, sqlerr.Translate(err, "creating rule version")
	}
	return result, nil
}

// GetVersionByID implements VersionRepository.
func (r *PostgresRepository) GetVersionByID(ctx context.Context, id uuid.UUID) (rule.Version, error) {
	row := r.db.QueryRow(ctx, `SELECT `+versionColumns+` FROM rule_versions WHERE id = $1`, id)
	result, err := scanVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Version{}, apperrors.NewNotFound("rule version not found", err)
		}
		return rule.Version{}, sqlerr.Translate(err, "fetching rule version")
	}
	return result, nil
}

// GetByRuleAndVersion implements VersionRepository.
func (r *PostgresRepository) GetByRuleAndVersion(ctx context.Context, ruleID uuid.UUID, version int) (rule.Version, error) {
	row := r.db.QueryRow(ctx, `SELECT `+versionColumns+` FROM rule_versions WHERE rule_id = $1 AND version = $2`, ruleID, version)
	result, err := scanVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Version{}, apperrors.NewNotFound("rule version not found", err)
		}
		return rule.Version{}, sqlerr.Translate(err, "fetching rule version")
	}
	return result, nil
}

// GetLatest implements VersionRepository.
func (r *PostgresRepository) GetLatest(ctx context.Context, ruleID uuid.UUID) (rule.Version, error) {
	row := r.db.QueryRow(ctx, `SELECT `+versionColumns+` FROM rule_versions WHERE rule_id = $1 ORDER BY version DESC LIMIT 1`, ruleID)
	result, err := scanVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Version{}, apperrors.NewNotFound("rule has no versions yet", err)
		}
		return rule.Version{}, sqlerr.Translate(err, "fetching latest rule version")
	}
	return result, nil
}

// GetLatestEnabled implements VersionRepository.
func (r *PostgresRepository) GetLatestEnabled(ctx context.Context, ruleID uuid.UUID) (rule.Version, error) {
	row := r.db.QueryRow(ctx, `SELECT `+versionColumns+` FROM rule_versions WHERE rule_id = $1 AND enabled = true ORDER BY version DESC LIMIT 1`, ruleID)
	result, err := scanVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Version{}, apperrors.NewNotFound("rule has no enabled version", err)
		}
		return rule.Version{}, sqlerr.Translate(err, "fetching latest enabled rule version")
	}
	return result, nil
}

// ListVersions implements VersionRepository.
func (r *PostgresRepository) ListVersions(ctx context.Context, ruleID uuid.UUID) ([]rule.Version, error) {
	rows, err := r.db.Query(ctx, `SELECT `+versionColumns+` FROM rule_versions WHERE rule_id = $1 ORDER BY version`, ruleID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing rule versions")
	}
	defer rows.Close()
	var out []rule.Version
	for rows.Next() {
		v, scanErr := scanVersion(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning rule version row")
		}
		out = append(out, v)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating rule versions")
}

// SetEnabled implements VersionRepository.
func (r *PostgresRepository) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) (rule.Version, error) {
	row := r.db.QueryRow(ctx, `UPDATE rule_versions SET enabled = $2 WHERE id = $1 RETURNING `+versionColumns, id, enabled)
	result, err := scanVersion(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Version{}, apperrors.NewNotFound("rule version not found", err)
		}
		return rule.Version{}, sqlerr.Translate(err, "updating rule version enabled flag")
	}
	return result, nil
}

// ---------------------------------------------------------------------
// detection_matches
// ---------------------------------------------------------------------

const matchColumns = `id, target_id, rule_id, rule_version, fingerprint, first_observed_at, last_observed_at, severity, confidence, status, explanation, created_at, updated_at`

func scanMatch(row pgx.Row) (rule.DetectionMatch, error) {
	var m rule.DetectionMatch
	err := row.Scan(&m.ID, &m.TargetID, &m.RuleID, &m.RuleVersion, &m.Fingerprint, &m.FirstObservedAt, &m.LastObservedAt,
		&m.Severity, &m.Confidence, &m.Status, &m.Explanation, &m.CreatedAt, &m.UpdatedAt)
	return m, err
}

// UpsertMatch implements MatchRepository.
func (r *PostgresRepository) UpsertMatch(ctx context.Context, m rule.DetectionMatch) (rule.DetectionMatch, bool, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO detection_matches (target_id, rule_id, rule_version, fingerprint, first_observed_at, last_observed_at, severity, confidence, status, explanation)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (fingerprint) DO UPDATE SET
			last_observed_at = GREATEST(detection_matches.last_observed_at, EXCLUDED.last_observed_at),
			explanation = EXCLUDED.explanation,
			updated_at = now()
		RETURNING `+matchColumns+`, (xmax = 0) AS inserted`,
		m.TargetID, m.RuleID, m.RuleVersion, m.Fingerprint, m.FirstObservedAt, m.LastObservedAt, m.Severity, m.Confidence, m.Status, m.Explanation)

	var (
		result  rule.DetectionMatch
		created bool
	)
	err := row.Scan(&result.ID, &result.TargetID, &result.RuleID, &result.RuleVersion, &result.Fingerprint,
		&result.FirstObservedAt, &result.LastObservedAt, &result.Severity, &result.Confidence, &result.Status,
		&result.Explanation, &result.CreatedAt, &result.UpdatedAt, &created)
	if err != nil {
		return rule.DetectionMatch{}, false, sqlerr.Translate(err, "upserting detection match")
	}
	return result, created, nil
}

// GetMatchByID implements MatchRepository.
func (r *PostgresRepository) GetMatchByID(ctx context.Context, id uuid.UUID) (rule.DetectionMatch, error) {
	row := r.db.QueryRow(ctx, `SELECT `+matchColumns+` FROM detection_matches WHERE id = $1`, id)
	result, err := scanMatch(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.DetectionMatch{}, apperrors.NewNotFound("detection match not found", err)
		}
		return rule.DetectionMatch{}, sqlerr.Translate(err, "fetching detection match")
	}
	return result, nil
}

// ListMatches implements MatchRepository.
func (r *PostgresRepository) ListMatches(ctx context.Context, filter MatchListFilter) (pagination.Page[rule.DetectionMatch], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[rule.DetectionMatch]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.RuleID != uuid.Nil {
		add("rule_id = $%d", filter.RuleID)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM detection_matches WHERE %s ORDER BY created_at, id LIMIT $%d`, matchColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[rule.DetectionMatch]{}, sqlerr.Translate(err, "listing detection matches")
	}
	defer rows.Close()

	var items []rule.DetectionMatch
	for rows.Next() {
		m, scanErr := scanMatch(rows)
		if scanErr != nil {
			return pagination.Page[rule.DetectionMatch]{}, sqlerr.Translate(scanErr, "scanning detection match row")
		}
		items = append(items, m)
	}
	page := pagination.Page[rule.DetectionMatch]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating detection matches")
}

// UpdateMatchStatus implements MatchRepository.
func (r *PostgresRepository) UpdateMatchStatus(ctx context.Context, id uuid.UUID, status rule.MatchStatus) (rule.DetectionMatch, error) {
	row := r.db.QueryRow(ctx, `UPDATE detection_matches SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+matchColumns, id, status)
	result, err := scanMatch(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.DetectionMatch{}, apperrors.NewNotFound("detection match not found", err)
		}
		return rule.DetectionMatch{}, sqlerr.Translate(err, "updating detection match status")
	}
	return result, nil
}

// ---------------------------------------------------------------------
// detection_evidence
// ---------------------------------------------------------------------

// AttachEvidence implements EvidenceRepository.
func (r *PostgresRepository) AttachEvidence(ctx context.Context, e rule.MatchEvidence) (rule.MatchEvidence, bool, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO detection_evidence (detection_match_id, source_type, source_id, role, observed_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (detection_match_id, source_type, source_id, role) DO UPDATE SET source_type = EXCLUDED.source_type
		RETURNING id, detection_match_id, source_type, source_id, role, observed_at, created_at, (xmax = 0) AS inserted`,
		e.DetectionMatchID, e.SourceType, e.SourceID, e.Role, e.ObservedAt)

	var (
		result  rule.MatchEvidence
		created bool
	)
	err := row.Scan(&result.ID, &result.DetectionMatchID, &result.SourceType, &result.SourceID, &result.Role, &result.ObservedAt, &result.CreatedAt, &created)
	if err != nil {
		return rule.MatchEvidence{}, false, sqlerr.Translate(err, "attaching detection evidence")
	}
	return result, created, nil
}

// ListByMatch implements EvidenceRepository.
func (r *PostgresRepository) ListByMatch(ctx context.Context, matchID uuid.UUID) ([]rule.MatchEvidence, error) {
	rows, err := r.db.Query(ctx, `SELECT id, detection_match_id, source_type, source_id, role, observed_at, created_at
		FROM detection_evidence WHERE detection_match_id = $1 ORDER BY observed_at`, matchID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing detection evidence")
	}
	defer rows.Close()
	var out []rule.MatchEvidence
	for rows.Next() {
		var e rule.MatchEvidence
		if err := rows.Scan(&e.ID, &e.DetectionMatchID, &e.SourceType, &e.SourceID, &e.Role, &e.ObservedAt, &e.CreatedAt); err != nil {
			return nil, sqlerr.Translate(err, "scanning detection evidence row")
		}
		out = append(out, e)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating detection evidence")
}

// ---------------------------------------------------------------------
// alerts
// ---------------------------------------------------------------------

const alertColumns = `id, target_id, detection_match_id, title, description, severity, confidence, status, investigation_id, first_observed_at, last_observed_at, created_at, updated_at`

func scanAlert(row pgx.Row) (rule.Alert, error) {
	var (
		a               rule.Alert
		investigationID pgtype.UUID
	)
	err := row.Scan(&a.ID, &a.TargetID, &a.DetectionMatchID, &a.Title, &a.Description, &a.Severity, &a.Confidence,
		&a.Status, &investigationID, &a.FirstObservedAt, &a.LastObservedAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return rule.Alert{}, err
	}
	a.InvestigationID = uuidPtr(investigationID)
	return a, nil
}

// UpsertAlert implements AlertRepository.
func (r *PostgresRepository) UpsertAlert(ctx context.Context, a rule.Alert) (rule.Alert, bool, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO alerts (target_id, detection_match_id, title, description, severity, confidence, status, first_observed_at, last_observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (detection_match_id) DO UPDATE SET
			last_observed_at = GREATEST(alerts.last_observed_at, EXCLUDED.last_observed_at),
			updated_at = now()
		RETURNING `+alertColumns+`, (xmax = 0) AS inserted`,
		a.TargetID, a.DetectionMatchID, a.Title, a.Description, a.Severity, a.Confidence, a.Status, a.FirstObservedAt, a.LastObservedAt)

	var (
		investigationID pgtype.UUID
		created         bool
		result          rule.Alert
	)
	err := row.Scan(&result.ID, &result.TargetID, &result.DetectionMatchID, &result.Title, &result.Description,
		&result.Severity, &result.Confidence, &result.Status, &investigationID, &result.FirstObservedAt, &result.LastObservedAt,
		&result.CreatedAt, &result.UpdatedAt, &created)
	if err != nil {
		return rule.Alert{}, false, sqlerr.Translate(err, "upserting alert")
	}
	result.InvestigationID = uuidPtr(investigationID)
	return result, created, nil
}

// GetAlertByID implements AlertRepository.
func (r *PostgresRepository) GetAlertByID(ctx context.Context, id uuid.UUID) (rule.Alert, error) {
	row := r.db.QueryRow(ctx, `SELECT `+alertColumns+` FROM alerts WHERE id = $1`, id)
	result, err := scanAlert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Alert{}, apperrors.NewNotFound("alert not found", err)
		}
		return rule.Alert{}, sqlerr.Translate(err, "fetching alert")
	}
	return result, nil
}

// ListAlerts implements AlertRepository.
func (r *PostgresRepository) ListAlerts(ctx context.Context, filter AlertListFilter) (pagination.Page[rule.Alert], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[rule.Alert]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM alerts WHERE %s ORDER BY created_at, id LIMIT $%d`, alertColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[rule.Alert]{}, sqlerr.Translate(err, "listing alerts")
	}
	defer rows.Close()

	var items []rule.Alert
	for rows.Next() {
		a, scanErr := scanAlert(rows)
		if scanErr != nil {
			return pagination.Page[rule.Alert]{}, sqlerr.Translate(scanErr, "scanning alert row")
		}
		items = append(items, a)
	}
	page := pagination.Page[rule.Alert]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating alerts")
}

// UpdateAlertStatus implements AlertRepository.
func (r *PostgresRepository) UpdateAlertStatus(ctx context.Context, id uuid.UUID, status rule.AlertStatus) (rule.Alert, error) {
	row := r.db.QueryRow(ctx, `UPDATE alerts SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+alertColumns, id, status)
	result, err := scanAlert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Alert{}, apperrors.NewNotFound("alert not found", err)
		}
		return rule.Alert{}, sqlerr.Translate(err, "updating alert status")
	}
	return result, nil
}

// SetInvestigation implements AlertRepository.
func (r *PostgresRepository) SetInvestigation(ctx context.Context, id uuid.UUID, investigationID uuid.UUID) (rule.Alert, error) {
	row := r.db.QueryRow(ctx, `UPDATE alerts SET investigation_id = $2, status = 'investigating', updated_at = now() WHERE id = $1 RETURNING `+alertColumns,
		id, investigationID)
	result, err := scanAlert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Alert{}, apperrors.NewNotFound("alert not found", err)
		}
		return rule.Alert{}, sqlerr.Translate(err, "setting alert investigation")
	}
	return result, nil
}

// ---------------------------------------------------------------------
// suppressions
// ---------------------------------------------------------------------

const suppressionColumns = `id, target_id, scope, scope_id, reason, created_by, created_at, expires_at, removed_at, removed_by`

func scanSuppression(row pgx.Row) (rule.Suppression, error) {
	var (
		s                    rule.Suppression
		expiresAt, removedAt pgtype.Timestamptz
	)
	err := row.Scan(&s.ID, &s.TargetID, &s.Scope, &s.ScopeID, &s.Reason, &s.CreatedBy, &s.CreatedAt, &expiresAt, &removedAt, &s.RemovedBy)
	if err != nil {
		return rule.Suppression{}, err
	}
	s.ExpiresAt = timePtr(expiresAt)
	s.RemovedAt = timePtr(removedAt)
	return s, nil
}

// CreateSuppression implements SuppressionRepository.
func (r *PostgresRepository) CreateSuppression(ctx context.Context, s rule.Suppression) (rule.Suppression, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO suppressions (target_id, scope, scope_id, reason, created_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING `+suppressionColumns,
		s.TargetID, s.Scope, s.ScopeID, s.Reason, s.CreatedBy, timeParam(s.ExpiresAt))
	result, err := scanSuppression(row)
	if err != nil {
		return rule.Suppression{}, sqlerr.Translate(err, "creating suppression")
	}
	return result, nil
}

// ListSuppressions implements SuppressionRepository.
func (r *PostgresRepository) ListSuppressions(ctx context.Context, filter SuppressionListFilter) (pagination.Page[rule.Suppression], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[rule.Suppression]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.Scope != "" {
		add("scope = $%d", filter.Scope)
	}
	if filter.ScopeID != uuid.Nil {
		add("scope_id = $%d", filter.ScopeID)
	}
	if filter.ActiveOnly {
		conditions = append(conditions, "removed_at IS NULL AND (expires_at IS NULL OR expires_at > now())")
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM suppressions WHERE %s ORDER BY created_at, id LIMIT $%d`, suppressionColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[rule.Suppression]{}, sqlerr.Translate(err, "listing suppressions")
	}
	defer rows.Close()

	var items []rule.Suppression
	for rows.Next() {
		s, scanErr := scanSuppression(rows)
		if scanErr != nil {
			return pagination.Page[rule.Suppression]{}, sqlerr.Translate(scanErr, "scanning suppression row")
		}
		items = append(items, s)
	}
	page := pagination.Page[rule.Suppression]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating suppressions")
}

// ActiveFor implements SuppressionRepository.
func (r *PostgresRepository) ActiveFor(ctx context.Context, scope rule.SuppressionScope, scopeID uuid.UUID, now time.Time) ([]rule.Suppression, error) {
	rows, err := r.db.Query(ctx, `SELECT `+suppressionColumns+` FROM suppressions
		WHERE scope = $1 AND scope_id = $2 AND removed_at IS NULL AND (expires_at IS NULL OR expires_at > $3)
		ORDER BY created_at`, scope, scopeID, now)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing active suppressions")
	}
	defer rows.Close()
	var out []rule.Suppression
	for rows.Next() {
		s, scanErr := scanSuppression(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning suppression row")
		}
		out = append(out, s)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating active suppressions")
}

// RemoveSuppression implements SuppressionRepository.
func (r *PostgresRepository) RemoveSuppression(ctx context.Context, id uuid.UUID, removedBy string) (rule.Suppression, error) {
	row := r.db.QueryRow(ctx, `UPDATE suppressions SET removed_at = now(), removed_by = $2 WHERE id = $1 RETURNING `+suppressionColumns,
		id, removedBy)
	result, err := scanSuppression(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rule.Suppression{}, apperrors.NewNotFound("suppression not found", err)
		}
		return rule.Suppression{}, sqlerr.Translate(err, "removing suppression")
	}
	return result, nil
}
