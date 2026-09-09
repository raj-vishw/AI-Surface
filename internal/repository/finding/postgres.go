package finding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"ai-surface-platform/internal/database"
	"ai-surface-platform/internal/domain/finding"
	apperrors "ai-surface-platform/internal/errors"
	"ai-surface-platform/internal/repository/pagination"
	"ai-surface-platform/internal/repository/sqlerr"
)

// PostgresRepository implements Repository, EvidenceRepository, and
// EventRepository, mirroring internal/repository/fingerprint.
// PostgresRepository's shape exactly — it depends on database.Executor so
// the same code works standalone or inside a transaction.
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
	_ EventRepository    = (*PostgresRepository)(nil)
)

const findingColumns = `
	id, target_id, asset_id, endpoint_id, scan_id, detector_id, detector_version,
	title, description, category, scope, severity, detector_severity, confidence,
	status, identity_key, remediation, "references", metadata,
	severity_overridden, severity_override_reason, severity_overridden_at,
	suppression_reason, first_seen, last_seen, resolved_at, created_at, updated_at`

func scanFinding(row pgx.Row) (finding.Finding, error) {
	var (
		f                    finding.Finding
		endpointID, scanID   pgtype.UUID
		confidence           float64
		referencesJSON       []byte
		severityOverriddenAt pgtype.Timestamptz
		resolvedAt           pgtype.Timestamptz
	)
	err := row.Scan(
		&f.ID, &f.TargetID, &f.AssetID, &endpointID, &scanID, &f.DetectorID, &f.DetectorVersion,
		&f.Title, &f.Description, &f.Category, &f.Scope, &f.Severity, &f.DetectorSeverity, &confidence,
		&f.Status, &f.IdentityKey, &f.Remediation, &referencesJSON, &f.Metadata,
		&f.SeverityOverridden, &f.SeverityOverrideReason, &severityOverriddenAt,
		&f.SuppressionReason, &f.FirstSeen, &f.LastSeen, &resolvedAt, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return finding.Finding{}, err
	}
	f.Confidence = finding.Confidence(confidence)
	f.EndpointID = uuidPtr(endpointID)
	f.ScanID = uuidPtr(scanID)
	if len(referencesJSON) > 0 {
		if err := json.Unmarshal(referencesJSON, &f.References); err != nil {
			return finding.Finding{}, fmt.Errorf("decoding references: %w", err)
		}
	}
	if severityOverriddenAt.Valid {
		t := severityOverriddenAt.Time
		f.SeverityOverriddenAt = &t
	}
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}
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
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (finding.Finding, error) {
	row := r.db.QueryRow(ctx, `SELECT `+findingColumns+` FROM findings WHERE id = $1`, id)
	f, err := scanFinding(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return finding.Finding{}, apperrors.NewNotFound("finding not found", err)
		}
		return finding.Finding{}, sqlerr.Translate(err, "fetching finding")
	}
	return f, nil
}

// Upsert implements Repository. See the interface doc comment for the
// merge semantics.
func (r *PostgresRepository) Upsert(ctx context.Context, f finding.Finding) (finding.Finding, bool, error) {
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now()
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = f.FirstSeen
	}
	if f.Status == "" {
		f.Status = finding.StatusOpen
	}
	if f.Metadata == nil {
		f.Metadata = map[string]any{}
	}
	if f.References == nil {
		f.References = []finding.Reference{}
	}
	referencesJSON, err := json.Marshal(f.References)
	if err != nil {
		return finding.Finding{}, false, apperrors.NewValidation("encoding references", err)
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO findings (
			target_id, asset_id, endpoint_id, scan_id, detector_id, detector_version,
			title, description, category, scope, severity, detector_severity, confidence,
			status, identity_key, remediation, "references", metadata,
			severity_overridden, severity_override_reason, severity_overridden_at,
			suppression_reason, first_seen, last_seen
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
		)
		ON CONFLICT (identity_key) DO UPDATE SET
			scan_id           = EXCLUDED.scan_id,
			detector_version  = EXCLUDED.detector_version,
			title             = EXCLUDED.title,
			description       = EXCLUDED.description,
			detector_severity = EXCLUDED.detector_severity,
			-- The effective severity keeps any human override in place
			-- (phase8.md §79); only when no override is active does it
			-- track the detector's latest output.
			severity          = CASE WHEN findings.severity_overridden THEN findings.severity ELSE EXCLUDED.detector_severity END,
			confidence        = EXCLUDED.confidence,
			remediation       = EXCLUDED.remediation,
			"references"      = EXCLUDED."references",
			metadata          = EXCLUDED.metadata,
			first_seen        = LEAST(findings.first_seen, EXCLUDED.first_seen),
			last_seen         = GREATEST(findings.last_seen, EXCLUDED.last_seen),
			updated_at        = now()
		RETURNING `+findingColumns+`, (xmax = 0) AS inserted`,
		f.TargetID, f.AssetID, uuidParam(f.EndpointID), uuidParam(f.ScanID), f.DetectorID, f.DetectorVersion,
		f.Title, f.Description, f.Category, f.Scope, f.Severity, f.DetectorSeverity, float64(f.Confidence),
		f.Status, f.IdentityKey, f.Remediation, referencesJSON, f.Metadata,
		f.SeverityOverridden, f.SeverityOverrideReason, timestampParam(f.SeverityOverriddenAt),
		f.SuppressionReason, f.FirstSeen, f.LastSeen,
	)

	result, created, err := scanUpsertedFinding(row)
	if err != nil {
		return finding.Finding{}, false, sqlerr.Translate(err, "upserting finding")
	}
	return result, created, nil
}

func timestampParam(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func scanUpsertedFinding(row pgx.Row) (finding.Finding, bool, error) {
	var (
		f                    finding.Finding
		endpointID, scanID   pgtype.UUID
		confidence           float64
		referencesJSON       []byte
		severityOverriddenAt pgtype.Timestamptz
		resolvedAt           pgtype.Timestamptz
		inserted             bool
	)
	err := row.Scan(
		&f.ID, &f.TargetID, &f.AssetID, &endpointID, &scanID, &f.DetectorID, &f.DetectorVersion,
		&f.Title, &f.Description, &f.Category, &f.Scope, &f.Severity, &f.DetectorSeverity, &confidence,
		&f.Status, &f.IdentityKey, &f.Remediation, &referencesJSON, &f.Metadata,
		&f.SeverityOverridden, &f.SeverityOverrideReason, &severityOverriddenAt,
		&f.SuppressionReason, &f.FirstSeen, &f.LastSeen, &resolvedAt, &f.CreatedAt, &f.UpdatedAt, &inserted,
	)
	if err != nil {
		return finding.Finding{}, false, err
	}
	f.Confidence = finding.Confidence(confidence)
	f.EndpointID = uuidPtr(endpointID)
	f.ScanID = uuidPtr(scanID)
	if len(referencesJSON) > 0 {
		if err := json.Unmarshal(referencesJSON, &f.References); err != nil {
			return finding.Finding{}, false, fmt.Errorf("decoding references: %w", err)
		}
	}
	if severityOverriddenAt.Valid {
		t := severityOverriddenAt.Time
		f.SeverityOverriddenAt = &t
	}
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}
	return f, inserted, nil
}

// UpdateStatus implements Repository.
func (r *PostgresRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status finding.Status, reason string) (finding.Finding, error) {
	var resolvedAtExpr string
	if status == finding.StatusResolved {
		resolvedAtExpr = "now()"
	} else {
		resolvedAtExpr = "NULL"
	}
	row := r.db.QueryRow(ctx, `
		UPDATE findings SET
			status              = $2,
			suppression_reason  = $3,
			resolved_at         = `+resolvedAtExpr+`,
			updated_at          = now()
		WHERE id = $1
		RETURNING `+findingColumns,
		id, status, reason,
	)
	f, err := scanFinding(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return finding.Finding{}, apperrors.NewNotFound("finding not found", err)
		}
		return finding.Finding{}, sqlerr.Translate(err, "updating finding status")
	}
	return f, nil
}

// OverrideSeverity implements Repository.
func (r *PostgresRepository) OverrideSeverity(ctx context.Context, id uuid.UUID, severity finding.Severity, reason string) (finding.Finding, error) {
	var (
		effectiveSeverity any
		overridden        bool
	)
	if severity == "" {
		// Clearing the override: the effective severity reverts to the
		// detector's own latest output.
		effectiveSeverity = nil
		overridden = false
	} else {
		effectiveSeverity = severity
		overridden = true
	}

	row := r.db.QueryRow(ctx, `
		UPDATE findings SET
			severity                  = COALESCE($2, detector_severity),
			severity_overridden       = $3,
			severity_override_reason  = $4,
			severity_overridden_at    = CASE WHEN $3 THEN now() ELSE NULL END,
			updated_at                = now()
		WHERE id = $1
		RETURNING `+findingColumns,
		id, effectiveSeverity, overridden, reason,
	)
	f, err := scanFinding(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return finding.Finding{}, apperrors.NewNotFound("finding not found", err)
		}
		return finding.Finding{}, sqlerr.Translate(err, "overriding finding severity")
	}
	return f, nil
}

// ResolveMissing implements Repository.
func (r *PostgresRepository) ResolveMissing(ctx context.Context, assetID uuid.UUID, stillDetected []uuid.UUID) ([]finding.Finding, error) {
	rows, err := r.db.Query(ctx, `
		UPDATE findings SET status = 'resolved', resolved_at = now(), updated_at = now()
		WHERE asset_id = $1 AND status IN ('open', 'reopened') AND NOT (id = ANY($2))
		RETURNING `+findingColumns,
		assetID, stillDetectedParam(stillDetected),
	)
	if err != nil {
		return nil, sqlerr.Translate(err, "resolving missing findings")
	}
	defer rows.Close()

	var items []finding.Finding
	for rows.Next() {
		f, scanErr := scanFinding(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning finding row")
		}
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		return nil, sqlerr.Translate(err, "iterating findings")
	}
	return items, nil
}

// stillDetectedParam converts nil/empty into a valid (empty) uuid array
// parameter — "= ANY('{}')" is always false, matching MarkInactiveExcept's
// identical convention elsewhere in this project.
func stillDetectedParam(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

// List implements Repository.
func (r *PostgresRepository) List(ctx context.Context, filter ListFilter) (pagination.Page[finding.Finding], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[finding.Finding]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.EndpointID != uuid.Nil {
		add("endpoint_id = $%d", filter.EndpointID)
	}
	if filter.Category != "" {
		add("category = $%d", filter.Category)
	}
	if filter.Severity != "" {
		add("severity = $%d", filter.Severity)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if filter.DetectorID != "" {
		add("detector_id = $%d", filter.DetectorID)
	}
	if filter.MinConfidence > 0 {
		add("confidence >= $%d", filter.MinConfidence)
	}
	if filter.ScanID != nil {
		add("scan_id = $%d", *filter.ScanID)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, limit+1)
	query := fmt.Sprintf(`
		SELECT %s FROM findings
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, findingColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[finding.Finding]{}, sqlerr.Translate(err, "listing findings")
	}
	defer rows.Close()

	var items []finding.Finding
	for rows.Next() {
		f, scanErr := scanFinding(rows)
		if scanErr != nil {
			return pagination.Page[finding.Finding]{}, sqlerr.Translate(scanErr, "scanning finding row")
		}
		items = append(items, f)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[finding.Finding]{}, sqlerr.Translate(err, "iterating findings")
	}

	page := pagination.Page[finding.Finding]{Items: items}
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

const evidenceColumns = `id, finding_id, source, evidence_type, evidence_data, evidence_fingerprint, confidence, observed_at, created_at`

func scanEvidence(row pgx.Row) (finding.Evidence, error) {
	var (
		e          finding.Evidence
		fp         string
		confidence float64
	)
	err := row.Scan(&e.ID, &e.FindingID, &e.Source, &e.EvidenceType, &e.EvidenceData, &fp, &confidence, &e.ObservedAt, &e.CreatedAt)
	if err != nil {
		return finding.Evidence{}, err
	}
	e.Fingerprint = fp
	e.Confidence = finding.Confidence(confidence)
	return e, nil
}

// CreateEvidence implements EvidenceRepository.
func (r *PostgresRepository) CreateEvidence(ctx context.Context, e finding.Evidence) (finding.Evidence, bool, error) {
	if e.ObservedAt.IsZero() {
		e.ObservedAt = now()
	}
	if e.Source == "" {
		e.Source = "detection"
	}
	if e.EvidenceData == nil {
		e.EvidenceData = map[string]any{}
	}
	fp, err := finding.EvidenceFingerprint(e.EvidenceData)
	if err != nil {
		return finding.Evidence{}, false, apperrors.NewValidation("computing evidence fingerprint", err)
	}

	row := r.db.QueryRow(ctx, `
		INSERT INTO finding_evidence (finding_id, source, evidence_type, evidence_data, evidence_fingerprint, confidence, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (finding_id, source, evidence_fingerprint) DO NOTHING
		RETURNING `+evidenceColumns,
		e.FindingID, e.Source, e.EvidenceType, e.EvidenceData, fp, float64(e.Confidence), e.ObservedAt,
	)
	created, err := scanEvidence(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := r.getEvidenceByFingerprint(ctx, e.FindingID, e.Source, fp)
			if getErr != nil {
				return finding.Evidence{}, false, getErr
			}
			return existing, false, nil
		}
		return finding.Evidence{}, false, sqlerr.Translate(err, "creating finding evidence")
	}
	return created, true, nil
}

func (r *PostgresRepository) getEvidenceByFingerprint(ctx context.Context, findingID uuid.UUID, source, fp string) (finding.Evidence, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+evidenceColumns+` FROM finding_evidence
		WHERE finding_id = $1 AND source = $2 AND evidence_fingerprint = $3`,
		findingID, source, fp,
	)
	e, err := scanEvidence(row)
	if err != nil {
		return finding.Evidence{}, sqlerr.Translate(err, "fetching existing finding evidence")
	}
	return e, nil
}

// ListEvidenceByFinding implements EvidenceRepository.
func (r *PostgresRepository) ListEvidenceByFinding(ctx context.Context, filter EvidenceListFilter) (pagination.Page[finding.Evidence], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[finding.Evidence]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"finding_id = $1"}
	args := []any{filter.FindingID}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`
		SELECT %s FROM finding_evidence
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, evidenceColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[finding.Evidence]{}, sqlerr.Translate(err, "listing finding evidence")
	}
	defer rows.Close()

	var items []finding.Evidence
	for rows.Next() {
		e, scanErr := scanEvidence(rows)
		if scanErr != nil {
			return pagination.Page[finding.Evidence]{}, sqlerr.Translate(scanErr, "scanning finding evidence row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[finding.Evidence]{}, sqlerr.Translate(err, "iterating finding evidence")
	}

	page := pagination.Page[finding.Evidence]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

const eventColumns = `id, finding_id, scan_id, event_type, from_status, to_status, severity, confidence, reason, detected_at, created_at`

func scanEvent(row pgx.Row) (finding.Event, error) {
	var (
		e          finding.Event
		scanID     pgtype.UUID
		confidence float64
	)
	err := row.Scan(&e.ID, &e.FindingID, &scanID, &e.Type, &e.FromStatus, &e.ToStatus, &e.Severity, &confidence, &e.Reason, &e.DetectedAt, &e.CreatedAt)
	if err != nil {
		return finding.Event{}, err
	}
	e.ScanID = uuidPtr(scanID)
	e.Confidence = finding.Confidence(confidence)
	return e, nil
}

// CreateEvent implements EventRepository.
func (r *PostgresRepository) CreateEvent(ctx context.Context, e finding.Event) (finding.Event, error) {
	if e.DetectedAt.IsZero() {
		e.DetectedAt = now()
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO finding_events (finding_id, scan_id, event_type, from_status, to_status, severity, confidence, reason, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+eventColumns,
		e.FindingID, uuidParam(e.ScanID), e.Type, e.FromStatus, e.ToStatus, e.Severity, float64(e.Confidence), e.Reason, e.DetectedAt,
	)
	result, err := scanEvent(row)
	if err != nil {
		return finding.Event{}, sqlerr.Translate(err, "creating finding event")
	}
	return result, nil
}

// ListEvents implements EventRepository.
func (r *PostgresRepository) ListEvents(ctx context.Context, filter EventListFilter) (pagination.Page[finding.Event], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[finding.Event]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"finding_id = $1"}
	args := []any{filter.FindingID}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`
		SELECT %s FROM finding_events
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, eventColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[finding.Event]{}, sqlerr.Translate(err, "listing finding events")
	}
	defer rows.Close()

	var items []finding.Event
	for rows.Next() {
		e, scanErr := scanEvent(rows)
		if scanErr != nil {
			return pagination.Page[finding.Event]{}, sqlerr.Translate(scanErr, "scanning finding event row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[finding.Event]{}, sqlerr.Translate(err, "iterating finding events")
	}

	page := pagination.Page[finding.Event]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

// ListEventsByScan implements EventRepository.
func (r *PostgresRepository) ListEventsByScan(ctx context.Context, targetID, scanID uuid.UUID) ([]finding.Event, error) {
	columns := "fe.id, fe.finding_id, fe.scan_id, fe.event_type, fe.from_status, fe.to_status, fe.severity, fe.confidence, fe.reason, fe.detected_at, fe.created_at"
	rows, err := r.db.Query(ctx, `
		SELECT `+columns+` FROM finding_events fe
		JOIN findings f ON f.id = fe.finding_id
		WHERE f.target_id = $1 AND fe.scan_id = $2
		ORDER BY fe.created_at, fe.id`,
		targetID, scanID,
	)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing finding events for scan")
	}
	defer rows.Close()

	var items []finding.Event
	for rows.Next() {
		e, scanErr := scanEvent(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning finding event row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, sqlerr.Translate(err, "iterating finding events")
	}
	return items, nil
}
