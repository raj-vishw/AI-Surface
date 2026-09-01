//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/migrate"
)

// setupDB connects to the real PostgreSQL instance configured by the
// TEST_DATABASE_* environment variables (same convention as
// bootstrap_test.go), applies every migration, and returns a pool the
// caller must close. Every asset/target/endpoint persistence test in this
// package uses this — none of them mock PostgreSQL (phase2.md §38).
func setupDB(t *testing.T) *database.Pool {
	t.Helper()

	cfg := config.DatabaseConfig{
		Host:               getenv("TEST_DATABASE_HOST", "localhost"),
		Port:               getenvInt(t, "TEST_DATABASE_PORT", 5432),
		User:               getenv("TEST_DATABASE_USER", "airecon"),
		Password:           getenv("TEST_DATABASE_PASSWORD", "airecon"),
		Name:               getenv("TEST_DATABASE_NAME", "airecon"),
		SSLMode:            "disable",
		ConnectTimeout:     5 * time.Second,
		MaxOpenConnections: 20,
		MaxIdleConnections: 5,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := database.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("connecting to test database: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := migrate.Up(ctx, pool.Pool); err != nil {
		t.Fatalf("applying migrations: %v", err)
	}

	return pool
}
