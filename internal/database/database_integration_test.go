//go:build integration

package database

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"ai-recon-platform/internal/config"
)

// TestConnectAndHealthCheckAgainstRealDatabase requires a reachable
// PostgreSQL instance (e.g. `make dev-up`) and is excluded from the default
// `go test ./...` run. Run explicitly with:
//
//	go test -tags=integration ./internal/database/...
func TestConnectAndHealthCheckAgainstRealDatabase(t *testing.T) {
	cfg := config.DatabaseConfig{
		Host:               getenv("TEST_DATABASE_HOST", "localhost"),
		Port:               getenvInt(t, "TEST_DATABASE_PORT", 5432),
		User:               getenv("TEST_DATABASE_USER", "airecon"),
		Password:           getenv("TEST_DATABASE_PASSWORD", "airecon"),
		Name:               getenv("TEST_DATABASE_NAME", "airecon"),
		SSLMode:            "disable",
		ConnectTimeout:     5 * time.Second,
		MaxOpenConnections: 5,
		MaxIdleConnections: 2,
	}

	pool, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	defer pool.Close()

	if err := pool.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck() failed: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(t *testing.T, key string, fallback int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("invalid integer for %s: %v", key, err)
	}
	return n
}
