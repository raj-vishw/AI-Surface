package reporting

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"ai-surface-platform/internal/database"
	"ai-surface-platform/internal/domain/reporting"
	apperrors "ai-surface-platform/internal/errors"
	"ai-surface-platform/internal/repository/pagination"
	"ai-surface-platform/internal/repository/sqlerr"
)

// PostgresRepository implements every interface in this package.
type PostgresRepository struct {
	db database.Executor
}

// NewPostgresRepository builds a repository backed by db.
func NewPostgresRepository(db database.Executor) *PostgresRepository {
	return &PostgresRepository{db: db}
}

var (
	_ ReportRepository          = (*PostgresRepository)(nil)
	_ PackageRepository         = (*PostgresRepository)(nil)
	_ ItemRepository            = (*PostgresRepository)(nil)
	_ ControlEvidenceRepository = (*PostgresRepository)(nil)
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

func joinAnd(conditions []string) string {
	out := conditions[0]
	for _, c := range conditions[1:] {
		out += " AND " + c
	}
	return out
}

// ---------------------------------------------------------------------
// reports
// ---------------------------------------------------------------------

const reportColumns = `id, target_id, report_type, subject_id, version, title, content, status, content_hash,
	generated_by, generated_at, provider, model, prompt_version, approved_by, approved_at, approval_notes, created_at`

func scanReport(row pgx.Row) (reporting.Report, error) {
	var (
		r                              reporting.Report
		subjectID                      pgtype.UUID
		provider, model, promptVersion pgtype.Text
		approvedBy                     pgtype.Text
		approvedAt                     pgtype.Timestamptz
	)
	err := row.Scan(&r.ID, &r.TargetID, &r.ReportType, &subjectID, &r.Version, &r.Title, &r.Content, &r.Status,
		&r.ContentHash, &r.GeneratedBy, &r.GeneratedAt, &provider, &model, &promptVersion,
		&approvedBy, &approvedAt, &r.ApprovalNotes, &r.CreatedAt)
	if err != nil {
		return reporting.Report{}, err
	}
	r.SubjectID = uuidPtr(subjectID)
	r.Provider = textPtr(provider)
	r.Model = textPtr(model)
	r.PromptVersion = textPtr(promptVersion)
	r.ApprovedBy = textPtr(approvedBy)
	if approvedAt.Valid {
		t := approvedAt.Time
		r.ApprovedAt = &t
	}
	return r, nil
}

// CreateReport implements ReportRepository.
func (r *PostgresRepository) CreateReport(ctx context.Context, rep reporting.Report) (reporting.Report, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO reports (target_id, report_type, subject_id, version, title, content, status, content_hash,
			generated_by, provider, model, prompt_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING `+reportColumns,
		rep.TargetID, rep.ReportType, uuidParam(rep.SubjectID), rep.Version, rep.Title, rep.Content, rep.Status,
		rep.ContentHash, rep.GeneratedBy, textParam(rep.Provider), textParam(rep.Model), textParam(rep.PromptVersion))
	result, err := scanReport(row)
	if err != nil {
		return reporting.Report{}, apperrors.NewDatabase("creating report", err)
	}
	return result, nil
}

// GetReportByID implements ReportRepository.
func (r *PostgresRepository) GetReportByID(ctx context.Context, id uuid.UUID) (reporting.Report, error) {
	row := r.db.QueryRow(ctx, `SELECT `+reportColumns+` FROM reports WHERE id = $1`, id)
	result, err := scanReport(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return reporting.Report{}, apperrors.NewNotFound("report not found", err)
		}
		return reporting.Report{}, apperrors.NewDatabase("fetching report", err)
	}
	return result, nil
}

// ListReports implements ReportRepository.
func (r *PostgresRepository) ListReports(ctx context.Context, filter ReportListFilter) (pagination.Page[reporting.Report], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[reporting.Report]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.ReportType != "" {
		add("report_type = $%d", filter.ReportType)
	}
	if filter.SubjectID != uuid.Nil {
		add("subject_id = $%d", filter.SubjectID)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM reports WHERE %s ORDER BY created_at, id LIMIT $%d`, reportColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[reporting.Report]{}, apperrors.NewDatabase("listing reports", err)
	}
	defer rows.Close()

	var items []reporting.Report
	for rows.Next() {
		rep, scanErr := scanReport(rows)
		if scanErr != nil {
			return pagination.Page[reporting.Report]{}, apperrors.NewDatabase("scanning report row", scanErr)
		}
		items = append(items, rep)
	}
	page := pagination.Page[reporting.Report]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	if rows.Err() != nil {
		return pagination.Page[reporting.Report]{}, sqlerr.Translate(rows.Err(), "iterating reports")
	}
	return page, nil
}

// LatestVersion implements ReportRepository.
func (r *PostgresRepository) LatestVersion(ctx context.Context, targetID uuid.UUID, reportType reporting.Type, subjectID *uuid.UUID) (int, error) {
	var version *int
	var err error
	if subjectID == nil {
		err = r.db.QueryRow(ctx, `
			SELECT max(version) FROM reports WHERE target_id = $1 AND report_type = $2 AND subject_id IS NULL`,
			targetID, reportType).Scan(&version)
	} else {
		err = r.db.QueryRow(ctx, `
			SELECT max(version) FROM reports WHERE target_id = $1 AND report_type = $2 AND subject_id = $3`,
			targetID, reportType, *subjectID).Scan(&version)
	}
	if err != nil {
		return 0, apperrors.NewDatabase("finding latest report version", err)
	}
	if version == nil {
		return 0, nil
	}
	return *version, nil
}

// Approve implements ReportRepository.
func (r *PostgresRepository) Approve(ctx context.Context, id uuid.UUID, approvedBy, notes string) (reporting.Report, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE reports SET status = 'approved', approved_by = $2, approved_at = now(), approval_notes = $3
		WHERE id = $1 RETURNING `+reportColumns, id, approvedBy, notes)
	result, err := scanReport(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return reporting.Report{}, apperrors.NewNotFound("report not found", err)
		}
		return reporting.Report{}, apperrors.NewDatabase("approving report", err)
	}
	return result, nil
}

// SetStatus implements ReportRepository.
func (r *PostgresRepository) SetStatus(ctx context.Context, id uuid.UUID, status reporting.Status) (reporting.Report, error) {
	row := r.db.QueryRow(ctx, `UPDATE reports SET status = $2 WHERE id = $1 RETURNING `+reportColumns, id, status)
	result, err := scanReport(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return reporting.Report{}, apperrors.NewNotFound("report not found", err)
		}
		return reporting.Report{}, apperrors.NewDatabase("updating report status", err)
	}
	return result, nil
}

// ---------------------------------------------------------------------
// evidence_packages
// ---------------------------------------------------------------------

const packageColumns = `id, target_id, report_id, created_by, created_at`

func scanPackage(row pgx.Row) (reporting.Package, error) {
	var (
		p        reporting.Package
		reportID pgtype.UUID
	)
	err := row.Scan(&p.ID, &p.TargetID, &reportID, &p.CreatedBy, &p.CreatedAt)
	if err != nil {
		return reporting.Package{}, err
	}
	p.ReportID = uuidPtr(reportID)
	return p, nil
}

// CreatePackage implements PackageRepository.
func (r *PostgresRepository) CreatePackage(ctx context.Context, p reporting.Package) (reporting.Package, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO evidence_packages (target_id, report_id, created_by)
		VALUES ($1,$2,$3) RETURNING `+packageColumns,
		p.TargetID, uuidParam(p.ReportID), p.CreatedBy)
	result, err := scanPackage(row)
	if err != nil {
		return reporting.Package{}, apperrors.NewDatabase("creating evidence package", err)
	}
	return result, nil
}

// GetPackageByID implements PackageRepository.
func (r *PostgresRepository) GetPackageByID(ctx context.Context, id uuid.UUID) (reporting.Package, error) {
	row := r.db.QueryRow(ctx, `SELECT `+packageColumns+` FROM evidence_packages WHERE id = $1`, id)
	result, err := scanPackage(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return reporting.Package{}, apperrors.NewNotFound("evidence package not found", err)
		}
		return reporting.Package{}, apperrors.NewDatabase("fetching evidence package", err)
	}
	return result, nil
}

// ListPackages implements PackageRepository.
func (r *PostgresRepository) ListPackages(ctx context.Context, filter PackageListFilter) (pagination.Page[reporting.Package], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[reporting.Package]{}, apperrors.NewValidation("invalid pagination cursor", err)
	}
	limit := filter.Pagination.ResolveLimit()

	conditions := []string{"1=1"}
	args := []any{}
	if filter.TargetID != uuid.Nil {
		args = append(args, filter.TargetID)
		conditions = append(conditions, fmt.Sprintf("target_id = $%d", len(args)))
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM evidence_packages WHERE %s ORDER BY created_at, id LIMIT $%d`, packageColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[reporting.Package]{}, apperrors.NewDatabase("listing evidence packages", err)
	}
	defer rows.Close()

	var items []reporting.Package
	for rows.Next() {
		p, scanErr := scanPackage(rows)
		if scanErr != nil {
			return pagination.Page[reporting.Package]{}, apperrors.NewDatabase("scanning evidence package row", scanErr)
		}
		items = append(items, p)
	}
	page := pagination.Page[reporting.Package]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	if rows.Err() != nil {
		return pagination.Page[reporting.Package]{}, sqlerr.Translate(rows.Err(), "iterating evidence packages")
	}
	return page, nil
}

// ---------------------------------------------------------------------
// evidence_items
// ---------------------------------------------------------------------

const itemColumns = `id, package_id, item_type, reference_id, hash, "timestamp", created_at`

func scanItem(row pgx.Row) (reporting.Item, error) {
	var i reporting.Item
	err := row.Scan(&i.ID, &i.PackageID, &i.ItemType, &i.ReferenceID, &i.Hash, &i.Timestamp, &i.CreatedAt)
	return i, err
}

// CreateItems implements ItemRepository.
func (r *PostgresRepository) CreateItems(ctx context.Context, items []reporting.Item) ([]reporting.Item, error) {
	out := make([]reporting.Item, 0, len(items))
	for _, item := range items {
		row := r.db.QueryRow(ctx, `
			INSERT INTO evidence_items (package_id, item_type, reference_id, hash, "timestamp")
			VALUES ($1,$2,$3,$4,$5) RETURNING `+itemColumns,
			item.PackageID, item.ItemType, item.ReferenceID, item.Hash, item.Timestamp)
		saved, err := scanItem(row)
		if err != nil {
			return nil, apperrors.NewDatabase("creating evidence item", err)
		}
		out = append(out, saved)
	}
	return out, nil
}

// ListItemsByPackage implements ItemRepository.
func (r *PostgresRepository) ListItemsByPackage(ctx context.Context, packageID uuid.UUID) ([]reporting.Item, error) {
	rows, err := r.db.Query(ctx, `SELECT `+itemColumns+` FROM evidence_items WHERE package_id = $1 ORDER BY "timestamp"`, packageID)
	if err != nil {
		return nil, apperrors.NewDatabase("listing evidence items", err)
	}
	defer rows.Close()
	var out []reporting.Item
	for rows.Next() {
		i, scanErr := scanItem(rows)
		if scanErr != nil {
			return nil, apperrors.NewDatabase("scanning evidence item row", scanErr)
		}
		out = append(out, i)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating evidence items")
}

// ---------------------------------------------------------------------
// control_evidence
// ---------------------------------------------------------------------

const controlEvidenceColumns = `id, target_id, control_id, evidence_type, reference_id, description, collected_at, created_at`

func scanControlEvidence(row pgx.Row) (reporting.ControlEvidence, error) {
	var c reporting.ControlEvidence
	err := row.Scan(&c.ID, &c.TargetID, &c.ControlID, &c.EvidenceType, &c.ReferenceID, &c.Description, &c.CollectedAt, &c.CreatedAt)
	return c, err
}

// RecordControlEvidence implements ControlEvidenceRepository.
func (r *PostgresRepository) RecordControlEvidence(ctx context.Context, c reporting.ControlEvidence) (reporting.ControlEvidence, error) {
	row := r.db.QueryRow(ctx, `
		INSERT INTO control_evidence (target_id, control_id, evidence_type, reference_id, description, collected_at)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+controlEvidenceColumns,
		c.TargetID, c.ControlID, c.EvidenceType, c.ReferenceID, c.Description, c.CollectedAt)
	result, err := scanControlEvidence(row)
	if err != nil {
		return reporting.ControlEvidence{}, apperrors.NewDatabase("recording control evidence", err)
	}
	return result, nil
}

// ListControlEvidence implements ControlEvidenceRepository.
func (r *PostgresRepository) ListControlEvidence(ctx context.Context, filter ControlEvidenceListFilter) (pagination.Page[reporting.ControlEvidence], error) {
	cursor, err := pagination.DecodeCursor(filter.Pagination.Cursor)
	if err != nil {
		return pagination.Page[reporting.ControlEvidence]{}, apperrors.NewValidation("invalid pagination cursor", err)
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
	if filter.ControlID != "" {
		add("control_id = $%d", filter.ControlID)
	}
	if !cursor.CreatedAt.IsZero() {
		args = append(args, cursor.CreatedAt, cursor.ID)
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)

	query := fmt.Sprintf(`SELECT %s FROM control_evidence WHERE %s ORDER BY created_at, id LIMIT $%d`, controlEvidenceColumns, joinAnd(conditions), len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return pagination.Page[reporting.ControlEvidence]{}, apperrors.NewDatabase("listing control evidence", err)
	}
	defer rows.Close()

	var items []reporting.ControlEvidence
	for rows.Next() {
		c, scanErr := scanControlEvidence(rows)
		if scanErr != nil {
			return pagination.Page[reporting.ControlEvidence]{}, apperrors.NewDatabase("scanning control evidence row", scanErr)
		}
		items = append(items, c)
	}
	page := pagination.Page[reporting.ControlEvidence]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = pagination.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}.Encode()
	}
	if rows.Err() != nil {
		return pagination.Page[reporting.ControlEvidence]{}, sqlerr.Translate(rows.Err(), "iterating control evidence")
	}
	return page, nil
}

// DistinctControls implements ControlEvidenceRepository.
func (r *PostgresRepository) DistinctControls(ctx context.Context, targetID uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx, `SELECT DISTINCT control_id FROM control_evidence WHERE target_id = $1 ORDER BY control_id`, targetID)
	if err != nil {
		return nil, apperrors.NewDatabase("listing distinct controls", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, apperrors.NewDatabase("scanning control id", err)
		}
		out = append(out, id)
	}
	return out, sqlerr.Translate(rows.Err(), "iterating distinct controls")
}
