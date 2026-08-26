//go:build integration

package migrate

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestUpIsIdempotent requires a reachable PostgreSQL instance (e.g.
// `make dev-up`) and is excluded from the default `go test ./...` run. Run
// explicitly with:
//
//	go test -tags=integration ./internal/migrate/...
func TestUpIsIdempotent(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		dsn = "postgres://airecon:airecon@localhost:5432/airecon?sslmode=disable"
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connecting to database: %v", err)
	}
	defer pool.Close()

	applied, err := Up(context.Background(), pool)
	if err != nil {
		t.Fatalf("Up() failed: %v", err)
	}
	if len(applied) == 0 {
		t.Log("no migrations newly applied (already applied by a previous run) — continuing")
	}

	// Second call must be a no-op: nothing new should be applied.
	appliedAgain, err := Up(context.Background(), pool)
	if err != nil {
		t.Fatalf("second Up() call failed: %v", err)
	}
	if len(appliedAgain) != 0 {
		t.Fatalf("expected second Up() call to apply nothing, applied: %v", appliedAgain)
	}

	statuses, err := StatusReport(context.Background(), pool)
	if err != nil {
		t.Fatalf("StatusReport() failed: %v", err)
	}
	for _, s := range statuses {
		if !s.Applied {
			t.Errorf("expected migration %d (%s) to be applied", s.Version, s.Description)
		}
	}
}
