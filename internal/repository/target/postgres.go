package target

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ai-surface-platform/internal/database"
	"ai-surface-platform/internal/domain/target"
	apperrors "ai-surface-platform/internal/errors"
	"ai-surface-platform/internal/repository/pagination"
	"ai-surface-platform/internal/repository/sqlerr"
)

// PostgresRepository is the PostgreSQL-backed Repository implementation. It
// depends on database.Executor rather than *database.Pool directly so the
// same code works both standalone and inside a transaction (see
// database.Pool.WithTx).
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a Repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var _ Repository = (*PostgresRepository)(nil)

const targetColumns = `id, name, type, value, description, authorization_status, created_at, updated_at`

func scanTarget(row pgx.Row) (target.Target, error) {
	var t target.Target
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Value, &t.Description, &t.AuthorizationStatus, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

// Create implements Repository.
func (r *PostgresRepository) Create(ctx context.Context, t target.Target) (target.Target, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO targets (name, type, value, description, authorization_status)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+targetColumns,
		t.Name, t.Type, t.Value, t.Description, authorizationOrDefault(t.AuthorizationStatus),
	)
	created, err := scanTarget(row)
	if err != nil {
		return target.Target{}, sqlerr.Translate(err, "creating target")
	}
	return created, nil
}

func authorizationOrDefault(status target.AuthorizationStatus) target.AuthorizationStatus {
	if status == "" {
		return target.AuthorizationUnverified
	}
	return status
}

// GetByID implements Repository.
func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (target.Target, error) {
	row := r.db.QueryRow(ctx, `SELECT `+targetColumns+` FROM targets WHERE id = $1`, id)
	t, err := scanTarget(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target.Target{}, apperrors.NewNotFound("target not found", err)
		}
		return target.Target{}, sqlerr.Translate(err, "fetching target")
	}
	return t, nil
}

// GetByValue implements Repository.
func (r *PostgresRepository) GetByValue(ctx context.Context, typ target.Type, value string) (target.Target, error) {
	row := r.db.QueryRow(ctx, `SELECT `+targetColumns+` FROM targets WHERE type = $1 AND value = $2`, typ, value)
	t, err := scanTarget(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target.Target{}, apperrors.NewNotFound("target not found", err)
		}
		return target.Target{}, sqlerr.Translate(err, "fetching target")
	}
	return t, nil
}

// Update implements Repository.
func (r *PostgresRepository) Update(ctx context.Context, t target.Target) (target.Target, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE targets
		SET name = $2, description = $3, authorization_status = $4, updated_at = now()
		WHERE id = $1
		RETURNING `+targetColumns,
		t.ID, t.Name, t.Description, t.AuthorizationStatus,
	)
	updated, err := scanTarget(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target.Target{}, apperrors.NewNotFound("target not found", err)
		}
		return target.Target{}, sqlerr.Translate(err, "updating target")
	}
	return updated, nil
}

// List implements Repository.
func (r *PostgresRepository) List(ctx context.Context, filter ListFilter) (pagination.Page[target.Target], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[target.Target]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		conditions = append(conditions, fmt.Sprintf(clause, len(args)))
	}

	if filter.Type != "" {
		add("type = $%d", filter.Type)
	}
	if filter.AuthorizationStatus != "" {
		add("authorization_status = $%d", filter.AuthorizationStatus)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, limit+1)
	query := fmt.Sprintf(`
		SELECT %s FROM targets
		WHERE %s
		ORDER BY created_at, id
		LIMIT $%d`, targetColumns, joinAnd(conditions), len(args))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[target.Target]{}, sqlerr.Translate(err, "listing targets")
	}
	defer rows.Close()

	var items []target.Target
	for rows.Next() {
		t, scanErr := scanTarget(rows)
		if scanErr != nil {
			return pagination.Page[target.Target]{}, sqlerr.Translate(scanErr, "scanning target row")
		}
		items = append(items, t)
	}
	if err := rows.Err(); err != nil {
		return pagination.Page[target.Target]{}, sqlerr.Translate(err, "iterating targets")
	}

	page := pagination.Page[target.Target]{Items: items}
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
