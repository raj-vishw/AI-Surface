package database

import (
	"context"
	"testing"
	"time"

	"ai-recon-platform/internal/config"
)

// TestConnectFailsFastOnUnreachableHost exercises the error path (timeout
// handling and error wrapping) without requiring a real PostgreSQL server,
// so it can run as part of the normal (non-integration) test suite.
func TestConnectFailsFastOnUnreachableHost(t *testing.T) {
	cfg := config.DatabaseConfig{
		Host:               "127.0.0.1",
		Port:               1, // reserved port, nothing should be listening
		User:               "airecon",
		Password:           "airecon",
		Name:               "airecon",
		SSLMode:            "disable",
		ConnectTimeout:     500 * time.Millisecond,
		MaxOpenConnections: 5,
		MaxIdleConnections: 2,
	}

	start := time.Now()
	pool, err := Connect(context.Background(), cfg)
	elapsed := time.Since(start)

	if err == nil {
		pool.Close()
		t.Fatal("expected Connect to fail against an unreachable database")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Connect took too long to fail (%s); ConnectTimeout should bound this", elapsed)
	}
}

func TestHealthCheckOnUninitializedPool(t *testing.T) {
	var pool *Pool
	if err := pool.HealthCheck(context.Background()); err == nil {
		t.Fatal("expected HealthCheck on a nil pool to return an error")
	}
}
