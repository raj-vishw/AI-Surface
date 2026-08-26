//go:build integration

package integration

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"ai-recon-platform/internal/application"
	"ai-recon-platform/internal/config"
)

// TestApplicationBootstrapEndToEnd exercises the full internal/application
// DI container — Postgres, Redis, and the HTTP server together — against
// real infrastructure (e.g. `make dev-up`), the same integration this
// project's phase completion reports verify manually. Excluded from the
// default `go test ./...` run. Run explicitly with:
//
//	go test -tags=integration ./test/integration/...
func TestApplicationBootstrapEndToEnd(t *testing.T) {
	cfg := &config.Config{
		Application: config.ApplicationConfig{Name: "ai-recon-platform", Environment: "test"},
		Server: config.ServerConfig{
			Host:              "127.0.0.1",
			Port:              0, // overwritten below with a free port
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       2 * time.Second,
			WriteTimeout:      2 * time.Second,
			IdleTimeout:       2 * time.Second,
			ShutdownTimeout:   2 * time.Second,
		},
		Database: config.DatabaseConfig{
			Host:               getenv("TEST_DATABASE_HOST", "localhost"),
			Port:               getenvInt(t, "TEST_DATABASE_PORT", 5432),
			User:               getenv("TEST_DATABASE_USER", "airecon"),
			Password:           getenv("TEST_DATABASE_PASSWORD", "airecon"),
			Name:               getenv("TEST_DATABASE_NAME", "airecon"),
			SSLMode:            "disable",
			ConnectTimeout:     5 * time.Second,
			MaxOpenConnections: 5,
			MaxIdleConnections: 2,
		},
		Redis: config.RedisConfig{
			Address:        getenv("TEST_REDIS_ADDRESS", "localhost:6379"),
			ConnectTimeout: 5 * time.Second,
		},
		HTTPClient: config.HTTPClientConfig{
			Timeout:               2 * time.Second,
			MaxIdleConnections:    10,
			MaxConnectionsPerHost: 10,
			MaxResponseSize:       1024,
			MaxRedirects:          5,
		},
		Logging: config.LoggingConfig{Level: "error", Format: "json"},
	}
	cfg.Server.Port = freePort(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	app, err := application.New(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("application.New() failed: %v", err)
	}
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- app.Run(ctx) }()

	waitForServer(t, "http://"+cfg.Server.Addr()+"/health")

	resp, err := http.Get("http://" + cfg.Server.Addr() + "/ready")
	if err != nil {
		t.Fatalf("GET /ready: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected /ready to report 200 against real infrastructure, got %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("Run() returned error after shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after context cancellation")
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

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForServer(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec // url is built from a test-local ephemeral-port address, not external input
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready in time", url)
}
