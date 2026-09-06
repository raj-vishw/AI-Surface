package correlation

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
	"ai-recon-platform/internal/domain/correlation"
	apperrors "ai-recon-platform/internal/errors"
	"ai-recon-platform/internal/repository/pagination"
	"ai-recon-platform/internal/repository/sqlerr"
)

// PostgresRepository implements every interface in this package,
// mirroring internal/repository/rule.PostgresRepository's shape exactly.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var (
	_ Repository      = (*PostgresRepository)(nil)
	_ NodeRepository  = (*PostgresRepository)(nil)
	_ EdgeRepository  = (*PostgresRepository)(nil)
	_ ChainRepository = (*PostgresRepository)(nil)
	_ StageRepository = (*PostgresRepository)(nil)
)

func timePtr(v pgtype.Timestamptz) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
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

func joinAnd(conditions []string) string {
	out := conditions[0]
	for _, c := range conditions[1:] {
		out += " AND " + c
	}
	return out
}

// ---------------------------------------------------------------------
// correlations
// ---------------------------------------------------------------------

const correlationColumns = `id, target_id, title, description, status, severity, confidence, score, fingerprint, model_version,
	first_observed_at, last_observed_at, investigation_id, confirmed_by, confirmed_at, confirmation_notes,
	dismissed_by, dismissed_at, dismissal_reason, merged_into_id, merged_from_ids, split_from_id, created_at, updated_at`

func scanCorrelation(row pgx.Row) (correlation.Correlation, error) {
	var (
		c                                          correlation.Correlation
		investigationID, mergedIntoID, splitFromID pgtype.UUID
		confirmedAt, dismissedAt                   pgtype.Timestamptz
		mergedFromJSON                             []byte
	)
	err := row.Scan(&c.ID, &c.TargetID, &c.Title, &c.Description, &c.Status, &c.Severity, &c.Confidence, &c.Score,
		&c.Fingerprint, &c.ModelVersion, &c.FirstObservedAt, &c.LastObservedAt, &investigationID,
		&c.ConfirmedBy, &confirmedAt, &c.ConfirmationNotes, &c.DismissedBy, &dismissedAt, &c.DismissalReason,
		&mergedIntoID, &mergedFromJSON, &splitFromID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return correlation.Correlation{}, err
	}
	c.InvestigationID = uuidPtr(investigationID)
	c.MergedIntoID = uuidPtr(mergedIntoID)
	c.SplitFromID = uuidPtr(splitFromID)
	c.ConfirmedAt = timePtr(confirmedAt)
	c.DismissedAt = timePtr(dismissedAt)
	if len(mergedFromJSON) > 0 {
		if err := json.Unmarshal(mergedFromJSON, &c.MergedFromIDs); err != nil {
			return correlation.Correlation{}, fmt.Errorf("decoding merged_from_ids: %w", err)
		}
	}
	return c, nil
}

// UpsertCorrelation implements Repository.
func (r *PostgresRepository) UpsertCorrelation(ctx context.Context, c correlation.Correlation) (correlation.Correlation, bool, error) {
	mergedFromJSON, err := json.Marshal(nonNilUUIDs(c.MergedFromIDs))
	if err != nil {
		return correlation.Correlation{}, false, fmt.Errorf("encoding merged_from_ids: %w", err)
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO correlations (target_id, title, description, status, severity, confidence, score, fingerprint,
			model_version, first_observed_at, last_observed_at, merged_from_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (fingerprint) DO UPDATE SET
			last_observed_at = GREATEST(correlations.last_observed_at, EXCLUDED.last_observed_at),
			score = EXCLUDED.score, description = EXCLUDED.description, updated_at = now()
		RETURNING `+correlationColumns+`, (xmax = 0) AS inserted`,
		c.TargetID, c.Title, c.Description, c.Status, c.Severity, c.Confidence, c.Score, c.Fingerprint,
		c.ModelVersion, c.FirstObservedAt, c.LastObservedAt, mergedFromJSON)

	result, created, err := scanCorrelationWithInserted(row)
	if err != nil {
		return correlation.Correlation{}, false, sqlerr.Translate(err, "upserting correlation")
	}
	return result, created, nil
}

func scanCorrelationWithInserted(row pgx.Row) (correlation.Correlation, bool, error) {
	var (
		c                                          correlation.Correlation
		investigationID, mergedIntoID, splitFromID pgtype.UUID
		confirmedAt, dismissedAt                   pgtype.Timestamptz
		mergedFromJSON                             []byte
		inserted                                   bool
	)
	err := row.Scan(&c.ID, &c.TargetID, &c.Title, &c.Description, &c.Status, &c.Severity, &c.Confidence, &c.Score,
		&c.Fingerprint, &c.ModelVersion, &c.FirstObservedAt, &c.LastObservedAt, &investigationID,
		&c.ConfirmedBy, &confirmedAt, &c.ConfirmationNotes, &c.DismissedBy, &dismissedAt, &c.DismissalReason,
		&mergedIntoID, &mergedFromJSON, &splitFromID, &c.CreatedAt, &c.UpdatedAt, &inserted)
	if err != nil {
		return correlation.Correlation{}, false, err
	}
	c.InvestigationID = uuidPtr(investigationID)
	c.MergedIntoID = uuidPtr(mergedIntoID)
	c.SplitFromID = uuidPtr(splitFromID)
	c.ConfirmedAt = timePtr(confirmedAt)
	c.DismissedAt = timePtr(dismissedAt)
	if len(mergedFromJSON) > 0 {
		if err := json.Unmarshal(mergedFromJSON, &c.MergedFromIDs); err != nil {
			return correlation.Correlation{}, false, fmt.Errorf("decoding merged_from_ids: %w", err)
		}
	}
	return c, inserted, nil
}

func nonNilUUIDs(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

// CreateCorrelation implements Repository.
func (r *PostgresRepository) CreateCorrelation(ctx context.Context, c correlation.Correlation) (correlation.Correlation, error) {
	mergedFromJSON, err := json.Marshal(nonNilUUIDs(c.MergedFromIDs))
	if err != nil {
		return correlation.Correlation{}, fmt.Errorf("encoding merged_from_ids: %w", err)
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO correlations (target_id, title, description, status, severity, confidence, score, fingerprint,
			model_version, first_observed_at, last_observed_at, merged_from_ids, split_from_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING `+correlationColumns,
		c.TargetID, c.Title, c.Description, c.Status, c.Severity, c.Confidence, c.Score, c.Fingerprint,
		c.ModelVersion, c.FirstObservedAt, c.LastObservedAt, mergedFromJSON, uuidParam(c.SplitFromID))
	result, err := scanCorrelation(row)
	if err != nil {
		return correlation.Correlation{}, sqlerr.Translate(err, "creating correlation")
	}
	return result, nil
}

// GetCorrelationByID implements Repository.
func (r *PostgresRepository) GetCorrelationByID(ctx context.Context, id uuid.UUID) (correlation.Correlation, error) {
	row := r.db.QueryRow(ctx, `SELECT `+correlationColumns+` FROM correlations WHERE id = $1`, id)
	result, err := scanCorrelation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Correlation{}, apperrors.NewNotFound("correlation not found", err)
		}
		return correlation.Correlation{}, sqlerr.Translate(err, "fetching correlation")
	}
	return result, nil
}

// ListCorrelations implements Repository.
func (r *PostgresRepository) ListCorrelations(ctx context.Context, filter ListFilter) (pagination.Page[correlation.Correlation], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[correlation.Correlation]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.Confidence != "" {
		add("confidence = $%d", filter.Confidence)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM correlations WHERE %s ORDER BY created_at, id LIMIT $%d`, correlationColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[correlation.Correlation]{}, sqlerr.Translate(err, "listing correlations")
	}
	defer rows.Close()

	var items []correlation.Correlation
	for rows.Next() {
		c, scanErr := scanCorrelation(rows)
		if scanErr != nil {
			return pagination.Page[correlation.Correlation]{}, sqlerr.Translate(scanErr, "scanning correlation row")
		}
		items = append(items, c)
	}
	page := pagination.Page[correlation.Correlation]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating correlations")
}

// UpdateStatus implements Repository.
func (r *PostgresRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status correlation.Status) (correlation.Correlation, error) {
	row := r.db.QueryRow(ctx, `UPDATE correlations SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+correlationColumns, id, status)
	result, err := scanCorrelation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Correlation{}, apperrors.NewNotFound("correlation not found", err)
		}
		return correlation.Correlation{}, sqlerr.Translate(err, "updating correlation status")
	}
	return result, nil
}

// Confirm implements Repository.
func (r *PostgresRepository) Confirm(ctx context.Context, id uuid.UUID, confirmedBy, notes string) (correlation.Correlation, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE correlations SET status = 'confirmed', confirmed_by = $2, confirmed_at = now(), confirmation_notes = $3, updated_at = now()
		WHERE id = $1 RETURNING `+correlationColumns, id, confirmedBy, notes)
	result, err := scanCorrelation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Correlation{}, apperrors.NewNotFound("correlation not found", err)
		}
		return correlation.Correlation{}, sqlerr.Translate(err, "confirming correlation")
	}
	return result, nil
}

// Dismiss implements Repository.
func (r *PostgresRepository) Dismiss(ctx context.Context, id uuid.UUID, dismissedBy, reason string) (correlation.Correlation, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE correlations SET status = 'dismissed', dismissed_by = $2, dismissed_at = now(), dismissal_reason = $3, updated_at = now()
		WHERE id = $1 RETURNING `+correlationColumns, id, dismissedBy, reason)
	result, err := scanCorrelation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Correlation{}, apperrors.NewNotFound("correlation not found", err)
		}
		return correlation.Correlation{}, sqlerr.Translate(err, "dismissing correlation")
	}
	return result, nil
}

// SetInvestigation implements Repository.
func (r *PostgresRepository) SetInvestigation(ctx context.Context, id uuid.UUID, investigationID uuid.UUID) (correlation.Correlation, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE correlations SET investigation_id = $2, status = 'investigating', updated_at = now()
		WHERE id = $1 RETURNING `+correlationColumns, id, investigationID)
	result, err := scanCorrelation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Correlation{}, apperrors.NewNotFound("correlation not found", err)
		}
		return correlation.Correlation{}, sqlerr.Translate(err, "setting correlation investigation")
	}
	return result, nil
}

// MarkMergedInto implements Repository.
func (r *PostgresRepository) MarkMergedInto(ctx context.Context, id uuid.UUID, survivorID uuid.UUID) (correlation.Correlation, error) {
	row := r.db.QueryRow(ctx, `UPDATE correlations SET merged_into_id = $2, updated_at = now() WHERE id = $1 RETURNING `+correlationColumns, id, survivorID)
	result, err := scanCorrelation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Correlation{}, apperrors.NewNotFound("correlation not found", err)
		}
		return correlation.Correlation{}, sqlerr.Translate(err, "marking correlation merged")
	}
	return result, nil
}

// AppendMergedFrom implements Repository.
func (r *PostgresRepository) AppendMergedFrom(ctx context.Context, survivorID uuid.UUID, mergedIDs []uuid.UUID) (correlation.Correlation, error) {
	addition, err := json.Marshal(mergedIDs)
	if err != nil {
		return correlation.Correlation{}, fmt.Errorf("encoding merged ids: %w", err)
	}
	row := r.db.QueryRow(ctx, `
		UPDATE correlations SET merged_from_ids = merged_from_ids || $2::jsonb, updated_at = now()
		WHERE id = $1 RETURNING `+correlationColumns, survivorID, addition)
	result, err := scanCorrelation(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Correlation{}, apperrors.NewNotFound("correlation not found", err)
		}
		return correlation.Correlation{}, sqlerr.Translate(err, "appending merged_from_ids")
	}
	return result, nil
}

// ---------------------------------------------------------------------
// correlation_nodes
// ---------------------------------------------------------------------

const nodeColumns = `id, correlation_id, type, reference_id, role, "timestamp", attributes, created_at`

func scanNode(row pgx.Row) (correlation.Node, error) {
	var (
		n         correlation.Node
		attrsJSON []byte
	)
	err := row.Scan(&n.ID, &n.CorrelationID, &n.Type, &n.ReferenceID, &n.Role, &n.Timestamp, &attrsJSON, &n.CreatedAt)
	if err != nil {
		return correlation.Node{}, err
	}
	if len(attrsJSON) > 0 {
		if err := json.Unmarshal(attrsJSON, &n.Attributes); err != nil {
			return correlation.Node{}, fmt.Errorf("decoding node attributes: %w", err)
		}
	}
	return n, nil
}

// CreateNode implements NodeRepository.
func (r *PostgresRepository) CreateNode(ctx context.Context, n correlation.Node) (correlation.Node, bool, error) {
	if n.Attributes == nil {
		n.Attributes = map[string]any{}
	}
	attrsJSON, err := json.Marshal(n.Attributes)
	if err != nil {
		return correlation.Node{}, false, fmt.Errorf("encoding node attributes: %w", err)
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO correlation_nodes (correlation_id, type, reference_id, role, "timestamp", attributes)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (correlation_id, type, reference_id) DO UPDATE SET type = EXCLUDED.type
		RETURNING `+nodeColumns+`, (xmax = 0) AS inserted`,
		n.CorrelationID, n.Type, n.ReferenceID, n.Role, n.Timestamp, attrsJSON)

	var (
		result   correlation.Node
		attrsOut []byte
		created  bool
	)
	err = row.Scan(&result.ID, &result.CorrelationID, &result.Type, &result.ReferenceID, &result.Role,
		&result.Timestamp, &attrsOut, &result.CreatedAt, &created)
	if err != nil {
		return correlation.Node{}, false, sqlerr.Translate(err, "creating correlation node")
	}
	if len(attrsOut) > 0 {
		if err := json.Unmarshal(attrsOut, &result.Attributes); err != nil {
			return correlation.Node{}, false, fmt.Errorf("decoding node attributes: %w", err)
		}
	}
	return result, created, nil
}

// ListNodes implements NodeRepository.
func (r *PostgresRepository) ListNodes(ctx context.Context, correlationID uuid.UUID) ([]correlation.Node, error) {
	rows, err := r.db.Query(ctx, `SELECT `+nodeColumns+` FROM correlation_nodes WHERE correlation_id = $1 ORDER BY "timestamp"`, correlationID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing correlation nodes")
	}
	defer rows.Close()
	var out []correlation.Node
	for rows.Next() {
		n, scanErr := scanNode(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning correlation node row")
		}
		out = append(out, n)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating correlation nodes")
}

// ReassignNodes implements NodeRepository.
func (r *PostgresRepository) ReassignNodes(ctx context.Context, nodeIDs []uuid.UUID, newCorrelationID uuid.UUID) error {
	if len(nodeIDs) == 0 {
		return nil
	}
	_, err := r.db.Exec(ctx, `UPDATE correlation_nodes SET correlation_id = $2 WHERE id = ANY($1)`, nodeIDs, newCorrelationID)
	return sqlerr.Translate(err, "reassigning correlation nodes")
}

// ---------------------------------------------------------------------
// correlation_edges
// ---------------------------------------------------------------------

const edgeColumns = `id, correlation_id, source_node_id, target_node_id, relationship, provenance, confidence, evidence, strategy_id, strategy_version, created_at`

func scanEdge(row pgx.Row) (correlation.Edge, error) {
	var e correlation.Edge
	err := row.Scan(&e.ID, &e.CorrelationID, &e.SourceNodeID, &e.TargetNodeID, &e.Relationship, &e.Provenance,
		&e.Confidence, &e.Evidence, &e.StrategyID, &e.StrategyVersion, &e.CreatedAt)
	return e, err
}

// CreateEdge implements EdgeRepository.
func (r *PostgresRepository) CreateEdge(ctx context.Context, e correlation.Edge) (correlation.Edge, bool, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO correlation_edges (correlation_id, source_node_id, target_node_id, relationship, provenance, confidence, evidence, strategy_id, strategy_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (correlation_id, source_node_id, target_node_id, relationship, strategy_id) DO UPDATE SET evidence = EXCLUDED.evidence
		RETURNING `+edgeColumns+`, (xmax = 0) AS inserted`,
		e.CorrelationID, e.SourceNodeID, e.TargetNodeID, e.Relationship, e.Provenance, e.Confidence, e.Evidence, e.StrategyID, e.StrategyVersion)

	var (
		result  correlation.Edge
		created bool
	)
	err := row.Scan(&result.ID, &result.CorrelationID, &result.SourceNodeID, &result.TargetNodeID, &result.Relationship,
		&result.Provenance, &result.Confidence, &result.Evidence, &result.StrategyID, &result.StrategyVersion, &result.CreatedAt, &created)
	if err != nil {
		return correlation.Edge{}, false, sqlerr.Translate(err, "creating correlation edge")
	}
	return result, created, nil
}

// ListEdges implements EdgeRepository.
func (r *PostgresRepository) ListEdges(ctx context.Context, correlationID uuid.UUID) ([]correlation.Edge, error) {
	rows, err := r.db.Query(ctx, `SELECT `+edgeColumns+` FROM correlation_edges WHERE correlation_id = $1 ORDER BY created_at`, correlationID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing correlation edges")
	}
	defer rows.Close()
	var out []correlation.Edge
	for rows.Next() {
		e, scanErr := scanEdge(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning correlation edge row")
		}
		out = append(out, e)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating correlation edges")
}

// EdgesTouching implements EdgeRepository.
func (r *PostgresRepository) EdgesTouching(ctx context.Context, nodeIDs []uuid.UUID) ([]correlation.Edge, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.Query(ctx, `SELECT `+edgeColumns+` FROM correlation_edges WHERE source_node_id = ANY($1) OR target_node_id = ANY($1) ORDER BY created_at`, nodeIDs)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing edges touching nodes")
	}
	defer rows.Close()
	var out []correlation.Edge
	for rows.Next() {
		e, scanErr := scanEdge(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning correlation edge row")
		}
		out = append(out, e)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating correlation edges")
}

// ReassignEdges implements EdgeRepository.
func (r *PostgresRepository) ReassignEdges(ctx context.Context, edgeIDs []uuid.UUID, newCorrelationID uuid.UUID) error {
	if len(edgeIDs) == 0 {
		return nil
	}
	_, err := r.db.Exec(ctx, `UPDATE correlation_edges SET correlation_id = $2 WHERE id = ANY($1)`, edgeIDs, newCorrelationID)
	return sqlerr.Translate(err, "reassigning correlation edges")
}

// ---------------------------------------------------------------------
// attack_chains
// ---------------------------------------------------------------------

const chainColumns = `id, correlation_id, name, description, confidence, severity, status, created_at, updated_at`

func scanChain(row pgx.Row) (correlation.AttackChain, error) {
	var c correlation.AttackChain
	err := row.Scan(&c.ID, &c.CorrelationID, &c.Name, &c.Description, &c.Confidence, &c.Severity, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

// CreateChain implements ChainRepository.
func (r *PostgresRepository) CreateChain(ctx context.Context, c correlation.AttackChain) (correlation.AttackChain, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO attack_chains (correlation_id, name, description, confidence, severity, status)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (correlation_id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
			confidence = EXCLUDED.confidence, severity = EXCLUDED.severity, updated_at = now()
		RETURNING `+chainColumns,
		c.CorrelationID, c.Name, c.Description, c.Confidence, c.Severity, c.Status)
	result, err := scanChain(row)
	if err != nil {
		return correlation.AttackChain{}, sqlerr.Translate(err, "creating attack chain")
	}
	return result, nil
}

// GetChainByCorrelationID implements ChainRepository.
func (r *PostgresRepository) GetChainByCorrelationID(ctx context.Context, correlationID uuid.UUID) (correlation.AttackChain, error) {
	row := r.db.QueryRow(ctx, `SELECT `+chainColumns+` FROM attack_chains WHERE correlation_id = $1`, correlationID)
	result, err := scanChain(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.AttackChain{}, apperrors.NewNotFound("attack chain not found", err)
		}
		return correlation.AttackChain{}, sqlerr.Translate(err, "fetching attack chain")
	}
	return result, nil
}

// GetChainByID implements ChainRepository.
func (r *PostgresRepository) GetChainByID(ctx context.Context, id uuid.UUID) (correlation.AttackChain, error) {
	row := r.db.QueryRow(ctx, `SELECT `+chainColumns+` FROM attack_chains WHERE id = $1`, id)
	result, err := scanChain(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.AttackChain{}, apperrors.NewNotFound("attack chain not found", err)
		}
		return correlation.AttackChain{}, sqlerr.Translate(err, "fetching attack chain")
	}
	return result, nil
}

// ListChains implements ChainRepository.
func (r *PostgresRepository) ListChains(ctx context.Context, pageParams pagination.Params) (pagination.Page[correlation.AttackChain], error) {
	cursor, err := pagination.DecodeCursor(pageParams.Cursor)
	if err != nil {
		return pagination.Page[correlation.AttackChain]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := pageParams.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM attack_chains WHERE %s ORDER BY created_at, id LIMIT $%d`, chainColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[correlation.AttackChain]{}, sqlerr.Translate(err, "listing attack chains")
	}
	defer rows.Close()

	var items []correlation.AttackChain
	for rows.Next() {
		c, scanErr := scanChain(rows)
		if scanErr != nil {
			return pagination.Page[correlation.AttackChain]{}, sqlerr.Translate(scanErr, "scanning attack chain row")
		}
		items = append(items, c)
	}
	page := pagination.Page[correlation.AttackChain]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	return page, sqlerr.Translate(rows.Err(), "iterating attack chains")
}

// UpdateChainStatus implements ChainRepository.
func (r *PostgresRepository) UpdateChainStatus(ctx context.Context, id uuid.UUID, status correlation.Status) (correlation.AttackChain, error) {
	row := r.db.QueryRow(ctx, `UPDATE attack_chains SET status = $2, updated_at = now() WHERE id = $1 RETURNING `+chainColumns, id, status)
	result, err := scanChain(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.AttackChain{}, apperrors.NewNotFound("attack chain not found", err)
		}
		return correlation.AttackChain{}, sqlerr.Translate(err, "updating attack chain status")
	}
	return result, nil
}

// ---------------------------------------------------------------------
// attack_chain_stages
// ---------------------------------------------------------------------

const stageColumns = `id, attack_chain_id, stage, "order", confidence, evidence, created_at`

func scanStage(row pgx.Row) (correlation.AttackChainStage, error) {
	var (
		s            correlation.AttackChainStage
		evidenceJSON []byte
	)
	err := row.Scan(&s.ID, &s.AttackChainID, &s.Stage, &s.Order, &s.Confidence, &evidenceJSON, &s.CreatedAt)
	if err != nil {
		return correlation.AttackChainStage{}, err
	}
	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &s.Evidence); err != nil {
			return correlation.AttackChainStage{}, fmt.Errorf("decoding stage evidence: %w", err)
		}
	}
	return s, nil
}

// CreateStage implements StageRepository.
func (r *PostgresRepository) CreateStage(ctx context.Context, s correlation.AttackChainStage) (correlation.AttackChainStage, error) {
	evidenceJSON, err := json.Marshal(s.Evidence)
	if err != nil {
		return correlation.AttackChainStage{}, fmt.Errorf("encoding stage evidence: %w", err)
	}
	row := r.db.QueryRow(ctx, `
		INSERT INTO attack_chain_stages (attack_chain_id, stage, "order", confidence, evidence)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING `+stageColumns,
		s.AttackChainID, s.Stage, s.Order, s.Confidence, evidenceJSON)
	result, err := scanStage(row)
	if err != nil {
		return correlation.AttackChainStage{}, sqlerr.Translate(err, "creating attack chain stage")
	}
	return result, nil
}

// ListStages implements StageRepository.
func (r *PostgresRepository) ListStages(ctx context.Context, chainID uuid.UUID) ([]correlation.AttackChainStage, error) {
	rows, err := r.db.Query(ctx, `SELECT `+stageColumns+` FROM attack_chain_stages WHERE attack_chain_id = $1 ORDER BY "order"`, chainID)
	if err != nil {
		return nil, sqlerr.Translate(err, "listing attack chain stages")
	}
	defer rows.Close()
	var out []correlation.AttackChainStage
	for rows.Next() {
		s, scanErr := scanStage(rows)
		if scanErr != nil {
			return nil, sqlerr.Translate(scanErr, "scanning attack chain stage row")
		}
		out = append(out, s)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating attack chain stages")
}
