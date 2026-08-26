package redis

import (
	"context"
	"testing"
	"time"

	"ai-recon-platform/internal/config"
)

// TestConnectFailsFastOnUnreachableHost exercises the error path (timeout
// handling and error wrapping) without requiring a real Redis server, so it
// can run as part of the normal (non-integration) test suite.
func TestConnectFailsFastOnUnreachableHost(t *testing.T) {
	cfg := config.RedisConfig{
		Address:        "127.0.0.1:1", // reserved port, nothing should be listening
		ConnectTimeout: 500 * time.Millisecond,
	}

	start := time.Now()
	client, err := Connect(context.Background(), cfg)
	elapsed := time.Since(start)

	if err == nil {
		_ = client.Close()
		t.Fatal("expected Connect to fail against an unreachable redis")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Connect took too long to fail (%s); ConnectTimeout should bound this", elapsed)
	}
}

func TestHealthCheckOnUninitializedClient(t *testing.T) {
	var client *Client
	if err := client.HealthCheck(context.Background()); err == nil {
		t.Fatal("expected HealthCheck on a nil client to return an error")
	}
}
