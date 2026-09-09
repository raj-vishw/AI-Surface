// Package migrate implements a minimal, dependency-free SQL migration
// runner. Migrations are plain .sql files named "<sequence>_<description>.sql"
// (e.g. "000001_initial.sql") living in the repository's top-level
// migrations/ directory, embedded there (see migrations.FS) so
// `cmd/migrate` never depends on a filesystem path at runtime.
//
// Phase 1 intentionally ships only the migration bookkeeping table itself
// (schema_migrations) — no product tables exist yet. Later phases add their
// own numbered .sql files to migrations/.
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"ai-recon-platform/migrations"
)

// Migration is a single parsed migration file.
type Migration struct {
	Version     int
	Description string
	Filename    string
	SQL         string
}

// Load reads and sorts all embedded migrations by version. It fails if any
// filename does not match "<digits>_<description>.sql" or if two files
// share a version.
func Load() ([]Migration, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("reading embedded migrations: %w", err)
	}

	result := make([]Migration, 0, len(entries))
	seen := make(map[int]string)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		version, description, err := parseFilename(entry.Name())
		if err != nil {
			return nil, err
		}
		if existing, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", version, existing, entry.Name())
		}
		seen[version] = entry.Name()

		data, err := migrations.FS.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading migration %s: %w", entry.Name(), err)
		}

		result = append(result, Migration{
			Version:     version,
			Description: description,
			Filename:    entry.Name(),
			SQL:         string(data),
		})
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result, nil
}

func parseFilename(name string) (version int, description string, err error) {
	base := strings.TrimSuffix(name, ".sql")
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("migration filename %q must match <version>_<description>.sql", name)
	}
	version, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("migration filename %q must start with a numeric version: %w", name, err)
	}
	return version, parts[1], nil
}

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version     INTEGER PRIMARY KEY,
	description TEXT NOT NULL,
	applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

// Up applies all migrations that have not yet been recorded in
// schema_migrations, in ascending version order, each inside its own
// transaction. It returns the versions that were newly applied.
func Up(ctx context.Context, pool *pgxpool.Pool) ([]int, error) {
	if _, err := pool.Exec(ctx, createMigrationsTable); err != nil {
		return nil, fmt.Errorf("ensuring schema_migrations table exists: %w", err)
	}

	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return nil, err
	}

	pending, err := Load()
	if err != nil {
		return nil, err
	}

	var newlyApplied []int
	for _, m := range pending {
		if applied[m.Version] {
			continue
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return newlyApplied, fmt.Errorf("beginning transaction for migration %d: %w", m.Version, err)
		}

		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return newlyApplied, fmt.Errorf("applying migration %d (%s): %w", m.Version, m.Filename, err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, description) VALUES ($1, $2)`,
			m.Version, m.Description,
		); err != nil {
			_ = tx.Rollback(ctx)
			return newlyApplied, fmt.Errorf("recording migration %d: %w", m.Version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return newlyApplied, fmt.Errorf("committing migration %d: %w", m.Version, err)
		}

		newlyApplied = append(newlyApplied, m.Version)
	}

	return newlyApplied, nil
}

// Status reports which known migrations have and have not been applied.
type Status struct {
	Version     int
	Description string
	Applied     bool
}

// StatusReport returns the status of every embedded migration, in version
// order, against the current database state.
func StatusReport(ctx context.Context, pool *pgxpool.Pool) ([]Status, error) {
	if _, err := pool.Exec(ctx, createMigrationsTable); err != nil {
		return nil, fmt.Errorf("ensuring schema_migrations table exists: %w", err)
	}

	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return nil, err
	}

	pending, err := Load()
	if err != nil {
		return nil, err
	}

	report := make([]Status, 0, len(pending))
	for _, m := range pending {
		report = append(report, Status{
			Version:     m.Version,
			Description: m.Description,
			Applied:     applied[m.Version],
		})
	}
	return report, nil
}

// CurrentVersion returns the highest applied migration version, and false
// if none have been applied yet.
func CurrentVersion(ctx context.Context, pool *pgxpool.Pool) (int, bool, error) {
	if _, err := pool.Exec(ctx, createMigrationsTable); err != nil {
		return 0, false, fmt.Errorf("ensuring schema_migrations table exists: %w", err)
	}

	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return 0, false, err
	}

	current := 0
	found := false
	for version := range applied {
		if !found || version > current {
			current = version
			found = true
		}
	}
	return current, found, nil
}

func appliedVersions(ctx context.Context, pool *pgxpool.Pool) (map[int]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("querying applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scanning applied migration version: %w", err)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating applied migrations: %w", err)
	}
	return applied, nil
}
