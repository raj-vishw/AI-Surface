package investigation

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
	"ai-recon-platform/internal/domain/investigation"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/repository/sqlerr"
)

// PostgresRepository implements every interface in this package on one
// type — the same "one repository, several narrow interfaces" shape
// internal/repository/{asset,finding} already establish.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var (
	_ Repository             = (*PostgresRepository)(nil)
	_ EvidenceRepository     = (*PostgresRepository)(nil)
	_ TimelineRepository     = (*PostgresRepository)(nil)
	_ RelationshipRepository = (*PostgresRepository)(nil)
	_ HypothesisRepository   = (*PostgresRepository)(nil)
	_ NoteRepository         = (*PostgresRepository)(nil)
	_ ClusterRepository      = (*PostgresRepository)(nil)
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

func timestampParam(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func timePtr(v pgtype.Timestamptz) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
}

// encodeOffset/decodeOffset implement timeline pagination's simple
// numeric-offset cursor — see TimelineListFilter's doc comment for why
// this listing can't use the keyset (created_at, id) cursor every other
// List in this project uses.
func encodeOffset(n int) string {
	return fmt.Sprintf("o%d", n)
}

func decodeOffset(cursor string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(cursor, "o%d", &n); err != nil {
		return 0, fmt.Errorf("invalid timeline cursor: %w", err)
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

// --- investigations ---------------------------------------------------

const investigationColumns = `
	id, target_id, title, description, status, priority, severity, confidence,
	created_by, assigned_to, detected_at, first_observed_at, last_observed_at,
	version, created_at, updated_at, closed_at`

func scanInvestigation(row pgx.Row) (investigation.Investigation, error) {
	var (
		inv                                               investigation.Investigation
		detectedAt, firstObserved, lastObserved, closedAt pgtype.Timestamptz
	)
	err := row.Scan(
		&inv.ID, &inv.TargetID, &inv.Title, &inv.Description, &inv.Status, &inv.Priority, &inv.Severity, &inv.Confidence,
		&inv.CreatedBy, &inv.AssignedTo, &detectedAt, &firstObserved, &lastObserved,
		&inv.Version, &inv.CreatedAt, &inv.UpdatedAt, &closedAt,
	)
	if err != nil {
		return investigation.Investigation{}, err
	}
	inv.DetectedAt = timePtr(detectedAt)
	inv.FirstObservedAt = timePtr(firstObserved)
	inv.LastObservedAt = timePtr(lastObserved)
	inv.ClosedAt = timePtr(closedAt)
	return inv, nil
}

// Create implements Repository.
func (r *PostgresRepository) Create(ctx context.Context, inv investigation.Investigation) (investigation.Investigation, error) {
	if inv.Status == "" {
		inv.Status = investigation.StatusNew
	}
	if inv.Version == 0 {
		inv.Version = 1
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO investigations (
			target_id, title, description, status, priority, severity, confidence,
			created_by, assigned_to, detected_at, first_observed_at, last_observed_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING `+investigationColumns,
		inv.TargetID, inv.Title, inv.Description, inv.Status, inv.Priority, inv.Severity, inv.Confidence,
		inv.CreatedBy, inv.AssignedTo, timestampParam(inv.DetectedAt), timestampParam(inv.FirstObservedAt),
		timestampParam(inv.LastObservedAt), inv.Version,
	)
	result, err := scanInvestigation(row)
	if err != nil {
		return investigation.Investigation{}, sqlerr.Translate(err, "creating investigation")
	}
	return result, nil
}

// GetByID implements Repository.
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (investigation.Investigation, error) {
	row := r.db.QueryRow(ctx, `SELECT `+investigationColumns+` FROM investigations WHERE id = $1`, id)
	inv, err := scanInvestigation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return investigation.Investigation{}, apperrors.NewNotFound("investigation not found", err)
		}
		return investigation.Investigation{}, sqlerr.Translate(err, "fetching investigation")
	}
	return inv, nil
}

// List implements Repository.
func (r *PostgresRepository) List(ctx context.Context, filter ListFilter) (pagination.Page[investigation.Investigation], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[investigation.Investigation]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.Severity != "" {
		add("severity = $%d", filter.Severity)
	}
	if filter.Priority != "" {
		add("priority = $%d", filter.Priority)
	}
	if filter.AssignedTo != "" {
		add("assigned_to = $%d", filter.AssignedTo)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM investigations WHERE %s ORDER BY created_at, id LIMIT $%d`,
		investigationColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[investigation.Investigation]{}, sqlerr.Translate(err, "listing investigations")
	}
	defer rows.Close()

	var items []investigation.Investigation
	for rows.Next() {
		inv, scanErr := scanInvestigation(rows)
		if scanErr != nil {
			return pagination.Page[investigation.Investigation]{}, sqlerr.Translate(scanErr, "scanning investigation row")
		}
		items = append(items, inv)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[investigation.Investigation]{}, sqlerr.Translate(err, "iterating investigations")
	}

	page := pagination.Page[investigation.Investigation]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

// Update implements Repository — optimistic concurrency via expectedVersion.
func (r *PostgresRepository) Update(ctx context.Context, inv investigation.Investigation, expectedVersion int) (investigation.Investigation, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE investigations SET
			title = $3, description = $4, status = $5, priority = $6, severity = $7, confidence = $8,
			assigned_to = $9, version = version + 1, updated_at = now(),
			closed_at = CASE WHEN $5 = 'closed' THEN COALESCE(closed_at, now()) WHEN $5 <> 'closed' THEN NULL ELSE closed_at END
		WHERE id = $1 AND version = $2
		RETURNING `+investigationColumns,
		inv.ID, expectedVersion, inv.Title, inv.Description, inv.Status, inv.Priority, inv.Severity, inv.Confidence, inv.AssignedTo,
	)
	result, err := scanInvestigation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Either the id doesn't exist, or the version didn't match —
			// distinguish so a real not-found isn't reported as a
			// spurious conflict.
			if _, getErr := r.GetByID(ctx, inv.ID); getErr != nil {
				return investigation.Investigation{}, getErr
			}
			return investigation.Investigation{}, apperrors.NewConflict(
				"investigation was modified concurrently — reload and retry", err)
		}
		return investigation.Investigation{}, sqlerr.Translate(err, "updating investigation")
	}
	return result, nil
}

// UpdateFirstLastObserved implements Repository.
func (r *PostgresRepository) UpdateFirstLastObserved(ctx context.Context, id uuid.UUID, observedAt time.Time) (investigation.Investigation, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE investigations SET
			first_observed_at = LEAST(COALESCE(first_observed_at, $2), $2),
			last_observed_at  = GREATEST(COALESCE(last_observed_at, $2), $2),
			updated_at = now()
		WHERE id = $1
		RETURNING `+investigationColumns,
		id, observedAt,
	)
	result, err := scanInvestigation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return investigation.Investigation{}, apperrors.NewNotFound("investigation not found", err)
		}
		return investigation.Investigation{}, sqlerr.Translate(err, "updating investigation observed window")
	}
	return result, nil
}

// --- investigation_evidence ---------------------------------------------

const evidenceColumns = `id, investigation_id, source_type, source_id, relation_type, observed_at, added_at, added_by, created_at`

func scanEvidenceRef(row pgx.Row) (investigation.EvidenceRef, error) {
	var e investigation.EvidenceRef
	err := row.Scan(&e.ID, &e.InvestigationID, &e.SourceType, &e.SourceID, &e.RelationType, &e.ObservedAt, &e.AddedAt, &e.AddedBy, &e.CreatedAt)
	if err != nil {
		return investigation.EvidenceRef{}, err
	}
	return e, nil
}

// AttachEvidence implements EvidenceRepository.
func (r *PostgresRepository) AttachEvidence(ctx context.Context, e investigation.EvidenceRef) (investigation.EvidenceRef, bool, error) {
	if e.AddedAt.IsZero() {
		e.AddedAt = time.Now().UTC()
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO investigation_evidence (investigation_id, source_type, source_id, relation_type, observed_at, added_at, added_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (investigation_id, source_type, source_id) DO NOTHING
		RETURNING `+evidenceColumns,
		e.InvestigationID, e.SourceType, e.SourceID, e.RelationType, e.ObservedAt, e.AddedAt, e.AddedBy,
	)
	created, err := scanEvidenceRef(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			existing, getErr := r.getEvidenceRef(ctx, e.InvestigationID, e.SourceType, e.SourceID)
			if getErr != nil {
				return investigation.EvidenceRef{}, false, getErr
			}
			return existing, false, nil
		}
		return investigation.EvidenceRef{}, false, sqlerr.Translate(err, "attaching investigation evidence")
	}
	return created, true, nil
}

func (r *PostgresRepository) getEvidenceRef(ctx context.Context, investigationID uuid.UUID, sourceType investigation.EntityType, sourceID uuid.UUID) (investigation.EvidenceRef, error) {
	row := r.db.QueryRow(ctx, `SELECT `+evidenceColumns+` FROM investigation_evidence WHERE investigation_id = $1 AND source_type = $2 AND source_id = $3`,
		investigationID, sourceType, sourceID)
	e, err := scanEvidenceRef(row)
	if err != nil {
		return investigation.EvidenceRef{}, sqlerr.Translate(err, "fetching existing investigation evidence")
	}
	return e, nil
}

// ListEvidence implements EvidenceRepository.
func (r *PostgresRepository) ListEvidence(ctx context.Context, filter EvidenceListFilter) (pagination.Page[investigation.EvidenceRef], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[investigation.EvidenceRef]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"investigation_id = $1"}
	args := []any{filter.InvestigationID}
	if filter.SourceType != "" {
		args = append(args, filter.SourceType)
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", len(args)))
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM investigation_evidence WHERE %s ORDER BY created_at, id LIMIT $%d`,
		evidenceColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[investigation.EvidenceRef]{}, sqlerr.Translate(err, "listing investigation evidence")
	}
	defer rows.Close()

	var items []investigation.EvidenceRef
	for rows.Next() {
		e, scanErr := scanEvidenceRef(rows)
		if scanErr != nil {
			return pagination.Page[investigation.EvidenceRef]{}, sqlerr.Translate(scanErr, "scanning investigation evidence row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[investigation.EvidenceRef]{}, sqlerr.Translate(err, "iterating investigation evidence")
	}

	page := pagination.Page[investigation.EvidenceRef]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

// --- timeline_events -----------------------------------------------------

const timelineColumns = `id, target_id, investigation_id, "timestamp", event_type, source_type, source_id, title, description, severity, actor, metadata, created_at`

func scanTimelineEvent(row pgx.Row) (investigation.TimelineEvent, error) {
	var (
		e        investigation.TimelineEvent
		sourceID pgtype.UUID
		metadata []byte
	)
	err := row.Scan(&e.ID, &e.TargetID, &e.InvestigationID, &e.Timestamp, &e.Type, &e.SourceType, &sourceID,
		&e.Title, &e.Description, &e.Severity, &e.Actor, &metadata, &e.CreatedAt)
	if err != nil {
		return investigation.TimelineEvent{}, err
	}
	e.SourceID = uuidPtr(sourceID)
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &e.Metadata); err != nil {
			return investigation.TimelineEvent{}, fmt.Errorf("decoding metadata: %w", err)
		}
	}
	return e, nil
}

// AppendEvent implements TimelineRepository.
func (r *PostgresRepository) AppendEvent(ctx context.Context, e investigation.TimelineEvent) (investigation.TimelineEvent, error) {
	if e.Actor == "" {
		e.Actor = "system"
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO timeline_events (target_id, investigation_id, "timestamp", event_type, source_type, source_id, title, description, severity, actor, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING `+timelineColumns,
		e.TargetID, e.InvestigationID, e.Timestamp, e.Type, e.SourceType, uuidParam(e.SourceID),
		e.Title, e.Description, e.Severity, e.Actor, e.Metadata,
	)
	result, err := scanTimelineEvent(row)
	if err != nil {
		return investigation.TimelineEvent{}, sqlerr.Translate(err, "appending timeline event")
	}
	return result, nil
}

// ListTimeline implements TimelineRepository.
func (r *PostgresRepository) ListTimeline(ctx context.Context, filter TimelineListFilter) (pagination.Page[investigation.TimelineEvent], error) {
	limit := filter.Pagination.ResolveLimit()
	offset := 0
	if filter.Pagination.Cursor != "" {
		// Timeline pagination uses a simple numeric offset (encoded the
		// same opaque way) rather than the keyset cursor every other
		// listing uses, since ordering here is by timestamp (which is
		// not guaranteed unique) rather than (created_at, id) — see
		// decodeOffset.
		var err error
		offset, err = decodeOffset(filter.Pagination.Cursor)
		if err != nil {
			return pagination.Page[investigation.TimelineEvent]{}, apperrors.NewValidation("invalid pagination cursor", err)
		}
	}

	order := "ASC"
	if filter.NewestFirst {
		order = "DESC"
	}
	query := fmt.Sprintf(`SELECT %s FROM timeline_events WHERE investigation_id = $1 ORDER BY "timestamp" %s, id %s LIMIT $2 OFFSET $3`,
		timelineColumns, order, order)

	rows, err := r.db.Query(ctx, query, filter.InvestigationID, limit+1, offset)
	if err != nil {
		return pagination.Page[investigation.TimelineEvent]{}, sqlerr.Translate(err, "listing timeline events")
	}
	defer rows.Close()

	var items []investigation.TimelineEvent
	for rows.Next() {
		e, scanErr := scanTimelineEvent(rows)
		if scanErr != nil {
			return pagination.Page[investigation.TimelineEvent]{}, sqlerr.Translate(scanErr, "scanning timeline event row")
		}
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[investigation.TimelineEvent]{}, sqlerr.Translate(err, "iterating timeline events")
	}

	page := pagination.Page[investigation.TimelineEvent]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = encodeOffset(offset + limit)
	}
	return page, nil
}

// --- investigation_relationships -----------------------------------------

const relationshipColumns = `
	id, investigation_id, source_type, source_id, target_type, target_id,
	relationship_type, status, score, confidence, explanation, signals,
	rule_id, rule_version, created_at`

func scanRelationship(row pgx.Row) (investigation.Relationship, error) {
	var (
		rel        investigation.Relationship
		signalsRaw []byte
	)
	err := row.Scan(
		&rel.ID, &rel.InvestigationID, &rel.SourceType, &rel.SourceID, &rel.TargetType, &rel.TargetID,
		&rel.Type, &rel.Status, &rel.Score, &rel.Confidence, &rel.Explanation, &signalsRaw,
		&rel.RuleID, &rel.RuleVersion, &rel.CreatedAt,
	)
	if err != nil {
		return investigation.Relationship{}, err
	}
	if len(signalsRaw) > 0 {
		if err := json.Unmarshal(signalsRaw, &rel.Signals); err != nil {
			return investigation.Relationship{}, fmt.Errorf("decoding signals: %w", err)
		}
	}
	return rel, nil
}

// UpsertRelationship implements RelationshipRepository.
func (r *PostgresRepository) UpsertRelationship(ctx context.Context, rel investigation.Relationship) (investigation.Relationship, bool, error) {
	if rel.Signals == nil {
		rel.Signals = map[string]int{}
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO investigation_relationships (
			investigation_id, source_type, source_id, target_type, target_id,
			relationship_type, status, score, confidence, explanation, signals, rule_id, rule_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (investigation_id, source_type, source_id, target_type, target_id, relationship_type, rule_id)
		DO UPDATE SET
			status = EXCLUDED.status, score = EXCLUDED.score, confidence = EXCLUDED.confidence,
			explanation = EXCLUDED.explanation, signals = EXCLUDED.signals, rule_version = EXCLUDED.rule_version
		RETURNING `+relationshipColumns+`, (xmax = 0) AS inserted`,
		rel.InvestigationID, rel.SourceType, rel.SourceID, rel.TargetType, rel.TargetID,
		rel.Type, rel.Status, rel.Score, rel.Confidence, rel.Explanation, rel.Signals, rel.RuleID, rel.RuleVersion,
	)

	var (
		result   investigation.Relationship
		inserted bool
	)
	var signalsRaw []byte
	err := row.Scan(
		&result.ID, &result.InvestigationID, &result.SourceType, &result.SourceID, &result.TargetType, &result.TargetID,
		&result.Type, &result.Status, &result.Score, &result.Confidence, &result.Explanation, &signalsRaw,
		&result.RuleID, &result.RuleVersion, &result.CreatedAt, &inserted,
	)
	if err != nil {
		return investigation.Relationship{}, false, sqlerr.Translate(err, "upserting relationship")
	}
	if len(signalsRaw) > 0 {
		if err := json.Unmarshal(signalsRaw, &result.Signals); err != nil {
			return investigation.Relationship{}, false, fmt.Errorf("decoding signals: %w", err)
		}
	}
	return result, inserted, nil
}

// ListRelationships implements RelationshipRepository.
func (r *PostgresRepository) ListRelationships(ctx context.Context, filter RelationshipListFilter) (pagination.Page[investigation.Relationship], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[investigation.Relationship]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"investigation_id = $1"}
	args := []any{filter.InvestigationID}
	if filter.Status != "" {
		args = append(args, filter.Status)
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM investigation_relationships WHERE %s ORDER BY created_at, id LIMIT $%d`,
		relationshipColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[investigation.Relationship]{}, sqlerr.Translate(err, "listing relationships")
	}
	defer rows.Close()

	var items []investigation.Relationship
	for rows.Next() {
		rel, scanErr := scanRelationship(rows)
		if scanErr != nil {
			return pagination.Page[investigation.Relationship]{}, sqlerr.Translate(scanErr, "scanning relationship row")
		}
		items = append(items, rel)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[investigation.Relationship]{}, sqlerr.Translate(err, "iterating relationships")
	}

	page := pagination.Page[investigation.Relationship]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

// --- hypotheses / hypothesis_evidence -------------------------------------

const hypothesisColumns = `id, investigation_id, title, description, status, confidence, created_by, created_at, updated_at`

func scanHypothesis(row pgx.Row) (investigation.Hypothesis, error) {
	var h investigation.Hypothesis
	err := row.Scan(&h.ID, &h.InvestigationID, &h.Title, &h.Description, &h.Status, &h.Confidence, &h.CreatedBy, &h.CreatedAt, &h.UpdatedAt)
	return h, err
}

// CreateHypothesis implements HypothesisRepository.
func (r *PostgresRepository) CreateHypothesis(ctx context.Context, h investigation.Hypothesis) (investigation.Hypothesis, error) {
	if h.Status == "" {
		h.Status = investigation.HypothesisProposed
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO hypotheses (investigation_id, title, description, status, confidence, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+hypothesisColumns,
		h.InvestigationID, h.Title, h.Description, h.Status, h.Confidence, h.CreatedBy,
	)
	result, err := scanHypothesis(row)
	if err != nil {
		return investigation.Hypothesis{}, sqlerr.Translate(err, "creating hypothesis")
	}
	return result, nil
}

// GetHypothesis implements HypothesisRepository.
func (r *PostgresRepository) GetHypothesis(ctx context.Context, id uuid.UUID) (investigation.Hypothesis, error) {
	row := r.db.QueryRow(ctx, `SELECT `+hypothesisColumns+` FROM hypotheses WHERE id = $1`, id)
	h, err := scanHypothesis(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return investigation.Hypothesis{}, apperrors.NewNotFound("hypothesis not found", err)
		}
		return investigation.Hypothesis{}, sqlerr.Translate(err, "fetching hypothesis")
	}
	return h, nil
}

// ListHypotheses implements HypothesisRepository.
func (r *PostgresRepository) ListHypotheses(ctx context.Context, investigationID uuid.UUID) ([]investigation.Hypothesis, error) {
	rows, err := r.db.Query(ctx, `SELECT `+hypothesisColumns+` FROM hypotheses WHERE investigation_id = $1 ORDER BY created_at, id`, investigationID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing hypotheses")
	}
	defer rows.Close()
	var items []investigation.Hypothesis
	for rows.Next() {
		h, scanErr := scanHypothesis(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning hypothesis row")
		}
		items = append(items, h)
	}
	return items, sqlerr.Translate(rows.Err(), "iterating hypotheses")
}

// UpdateHypothesisStatus implements HypothesisRepository.
func (r *PostgresRepository) UpdateHypothesisStatus(ctx context.Context, id uuid.UUID, status investigation.HypothesisStatus, confidence investigation.Confidence) (investigation.Hypothesis, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE hypotheses SET status = $2, confidence = $3, updated_at = now()
		WHERE id = $1
		RETURNING `+hypothesisColumns,
		id, status, confidence,
	)
	h, err := scanHypothesis(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return investigation.Hypothesis{}, apperrors.NewNotFound("hypothesis not found", err)
		}
		return investigation.Hypothesis{}, sqlerr.Translate(err, "updating hypothesis status")
	}
	return h, nil
}

const hypothesisEvidenceColumns = `id, hypothesis_id, source_type, source_id, description, observed_at, created_at`

func scanHypothesisEvidence(row pgx.Row) (investigation.HypothesisEvidence, error) {
	var (
		e          investigation.HypothesisEvidence
		observedAt pgtype.Timestamptz
	)
	err := row.Scan(&e.ID, &e.HypothesisID, &e.SourceType, &e.SourceID, &e.Description, &observedAt, &e.CreatedAt)
	if err != nil {
		return investigation.HypothesisEvidence{}, err
	}
	if observedAt.Valid {
		e.ObservedAt = observedAt.Time
	}
	return e, nil
}

// AddHypothesisEvidence implements HypothesisRepository.
func (r *PostgresRepository) AddHypothesisEvidence(ctx context.Context, e investigation.HypothesisEvidence) (investigation.HypothesisEvidence, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO hypothesis_evidence (hypothesis_id, source_type, source_id, description, observed_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+hypothesisEvidenceColumns,
		e.HypothesisID, e.SourceType, e.SourceID, e.Description, timestampParam(nonZeroTime(e.ObservedAt)),
	)
	result, err := scanHypothesisEvidence(row)
	if err != nil {
		return investigation.HypothesisEvidence{}, sqlerr.Translate(err, "adding hypothesis evidence")
	}
	return result, nil
}

func nonZeroTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ListHypothesisEvidence implements HypothesisRepository.
func (r *PostgresRepository) ListHypothesisEvidence(ctx context.Context, hypothesisID uuid.UUID) ([]investigation.HypothesisEvidence, error) {
	rows, err := r.db.Query(ctx, `SELECT `+hypothesisEvidenceColumns+` FROM hypothesis_evidence WHERE hypothesis_id = $1 ORDER BY created_at, id`, hypothesisID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing hypothesis evidence")
	}
	defer rows.Close()
	var items []investigation.HypothesisEvidence
	for rows.Next() {
		e, scanErr := scanHypothesisEvidence(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning hypothesis evidence row")
		}
		items = append(items, e)
	}
	return items, sqlerr.Translate(rows.Err(), "iterating hypothesis evidence")
}

// --- investigation_notes ---------------------------------------------------

const noteColumns = `id, investigation_id, author_id, content, ai_generated, approved_by, approved_at, created_at`

func scanNote(row pgx.Row) (investigation.Note, error) {
	var (
		n          investigation.Note
		approvedAt pgtype.Timestamptz
	)
	err := row.Scan(&n.ID, &n.InvestigationID, &n.AuthorID, &n.Content, &n.AIGenerated, &n.ApprovedBy, &approvedAt, &n.CreatedAt)
	if err != nil {
		return investigation.Note{}, err
	}
	n.ApprovedAt = timePtr(approvedAt)
	return n, nil
}

// AddNote implements NoteRepository.
func (r *PostgresRepository) AddNote(ctx context.Context, n investigation.Note) (investigation.Note, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO investigation_notes (investigation_id, author_id, content, ai_generated)
		VALUES ($1, $2, $3, $4)
		RETURNING `+noteColumns,
		n.InvestigationID, n.AuthorID, n.Content, n.AIGenerated,
	)
	result, err := scanNote(row)
	if err != nil {
		return investigation.Note{}, sqlerr.Translate(err, "adding note")
	}
	return result, nil
}

// ListNotes implements NoteRepository.
func (r *PostgresRepository) ListNotes(ctx context.Context, investigationID uuid.UUID) ([]investigation.Note, error) {
	rows, err := r.db.Query(ctx, `SELECT `+noteColumns+` FROM investigation_notes WHERE investigation_id = $1 ORDER BY created_at, id`, investigationID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing notes")
	}
	defer rows.Close()
	var items []investigation.Note
	for rows.Next() {
		n, scanErr := scanNote(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning note row")
		}
		items = append(items, n)
	}
	return items, sqlerr.Translate(rows.Err(), "iterating notes")
}

// ApproveNote implements NoteRepository.
func (r *PostgresRepository) ApproveNote(ctx context.Context, id uuid.UUID, approvedBy string) (investigation.Note, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE investigation_notes SET approved_by = $2, approved_at = now()
		WHERE id = $1 RETURNING `+noteColumns, id, approvedBy)
	result, err := scanNote(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return investigation.Note{}, apperrors.NewNotFound("note not found", err)
		}
		return investigation.Note{}, sqlerr.Translate(err, "approving note")
	}
	return result, nil
}

// --- incident_clusters / incident_cluster_items ---------------------------

const clusterColumns = `id, target_id, title, confidence, status, accepted_investigation_id, created_at, updated_at`

func scanCluster(row pgx.Row) (investigation.IncidentCluster, error) {
	var (
		c          investigation.IncidentCluster
		acceptedID pgtype.UUID
	)
	err := row.Scan(&c.ID, &c.TargetID, &c.Title, &c.Confidence, &c.Status, &acceptedID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return investigation.IncidentCluster{}, err
	}
	c.AcceptedInvestigationID = uuidPtr(acceptedID)
	return c, nil
}

// CreateCluster implements ClusterRepository.
func (r *PostgresRepository) CreateCluster(ctx context.Context, c investigation.IncidentCluster) (investigation.IncidentCluster, error) {
	if c.Status == "" {
		c.Status = investigation.ClusterSuggested
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO incident_clusters (target_id, title, confidence, status)
		VALUES ($1, $2, $3, $4)
		RETURNING `+clusterColumns,
		c.TargetID, c.Title, c.Confidence, c.Status,
	)
	result, err := scanCluster(row)
	if err != nil {
		return investigation.IncidentCluster{}, sqlerr.Translate(err, "creating incident cluster")
	}
	return result, nil
}

// GetCluster implements ClusterRepository.
func (r *PostgresRepository) GetCluster(ctx context.Context, id uuid.UUID) (investigation.IncidentCluster, error) {
	row := r.db.QueryRow(ctx, `SELECT `+clusterColumns+` FROM incident_clusters WHERE id = $1`, id)
	c, err := scanCluster(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return investigation.IncidentCluster{}, apperrors.NewNotFound("incident cluster not found", err)
		}
		return investigation.IncidentCluster{}, sqlerr.Translate(err, "fetching incident cluster")
	}
	return c, nil
}

// ListClusters implements ClusterRepository.
func (r *PostgresRepository) ListClusters(ctx context.Context, filter ClusterListFilter) (pagination.Page[investigation.IncidentCluster], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[investigation.IncidentCluster]{}, apperrors.NewValidation("invalid pagination cursor", err)
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

	query := fmt.Sprintf(`SELECT %s FROM incident_clusters WHERE %s ORDER BY created_at, id LIMIT $%d`,
		clusterColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[investigation.IncidentCluster]{}, sqlerr.Translate(err, "listing incident clusters")
	}
	defer rows.Close()

	var items []investigation.IncidentCluster
	for rows.Next() {
		c, scanErr := scanCluster(rows)
		if scanErr != nil {
			return pagination.Page[investigation.IncidentCluster]{}, sqlerr.Translate(scanErr, "scanning incident cluster row")
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[investigation.IncidentCluster]{}, sqlerr.Translate(err, "iterating incident clusters")
	}

	page := pagination.Page[investigation.IncidentCluster]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, nil
}

// UpdateClusterStatus implements ClusterRepository.
func (r *PostgresRepository) UpdateClusterStatus(ctx context.Context, id uuid.UUID, status investigation.ClusterStatus, acceptedInvestigationID *uuid.UUID) (investigation.IncidentCluster, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE incident_clusters SET status = $2, accepted_investigation_id = $3, updated_at = now()
		WHERE id = $1
		RETURNING `+clusterColumns,
		id, status, uuidParam(acceptedInvestigationID),
	)
	c, err := scanCluster(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return investigation.IncidentCluster{}, apperrors.NewNotFound("incident cluster not found", err)
		}
		return investigation.IncidentCluster{}, sqlerr.Translate(err, "updating incident cluster status")
	}
	return c, nil
}

const clusterItemColumns = `id, cluster_id, source_type, source_id, created_at`

func scanClusterItem(row pgx.Row) (investigation.ClusterItem, error) {
	var i investigation.ClusterItem
	err := row.Scan(&i.ID, &i.ClusterID, &i.SourceType, &i.SourceID, &i.CreatedAt)
	return i, err
}

// AddClusterItem implements ClusterRepository.
func (r *PostgresRepository) AddClusterItem(ctx context.Context, item investigation.ClusterItem) (investigation.ClusterItem, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO incident_cluster_items (cluster_id, source_type, source_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (cluster_id, source_type, source_id) DO UPDATE SET source_type = EXCLUDED.source_type
		RETURNING `+clusterItemColumns,
		item.ClusterID, item.SourceType, item.SourceID,
	)
	result, err := scanClusterItem(row)
	if err != nil {
		return investigation.ClusterItem{}, sqlerr.Translate(err, "adding cluster item")
	}
	return result, nil
}

// ListClusterItems implements ClusterRepository.
func (r *PostgresRepository) ListClusterItems(ctx context.Context, clusterID uuid.UUID) ([]investigation.ClusterItem, error) {
	rows, err := r.db.Query(ctx, `SELECT `+clusterItemColumns+` FROM incident_cluster_items WHERE cluster_id = $1 ORDER BY created_at, id`, clusterID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing cluster items")
	}
	defer rows.Close()
	var items []investigation.ClusterItem
	for rows.Next() {
		i, scanErr := scanClusterItem(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning cluster item row")
		}
		items = append(items, i)
	}
	return items, sqlerr.Translate(rows.Err(), "iterating cluster items")
}
