//go:build integration

package redis

import (
	"context"
	"os"
	"testing"
	"time"

	"ai-recon-platform/internal/config"
)

// TestConnectAndHealthCheckAgainstRealRedis requires a reachable Redis
// instance (e.g. `make dev-up`) and is excluded from the default
// `go test ./...` run. Run explicitly with:
//
//	go test -tags=integration ./internal/redis/...
func TestConnectAndHealthCheckAgainstRealRedis(t *testing.T) {
	cfg := config.RedisConfig{
		Address:        getenv("TEST_REDIS_ADDRESS", "localhost:6379"),
		Password:       getenv("TEST_REDIS_PASSWORD", ""),
		Database:       0,
		ConnectTimeout: 5 * time.Second,
	}

	client, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	defer client.Close()

	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck() failed: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
