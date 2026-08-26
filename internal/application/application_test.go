package application

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"ai-recon-platform/internal/config"
)

// TestNewFailsCleanlyWhenDatabaseUnreachable exercises the composition
// (and cleanup-on-partial-failure) logic in New without requiring a real
// Postgres/Redis instance, so it runs as part of the default test suite.
// The happy path is covered by the end-to-end check against the docker
// compose dev environment (see docs / phase completion reports).
func TestNewFailsCleanlyWhenDatabaseUnreachable(t *testing.T) {
	cfg := &config.Config{
		Application: config.ApplicationConfig{
			Name:        "ai-recon-platform",
			Environment: "test",
		},
		Server: config.ServerConfig{
			Host:              "127.0.0.1",
			Port:              8080,
			ReadHeaderTimeout: time.Second,
			ReadTimeout:       time.Second,
			WriteTimeout:      time.Second,
			IdleTimeout:       time.Second,
			ShutdownTimeout:   time.Second,
		},
		Database: config.DatabaseConfig{
			Host:               "127.0.0.1",
			Port:               1, // reserved port, nothing listening
			User:               "airecon",
			Password:           "airecon",
			Name:               "airecon",
			SSLMode:            "disable",
			ConnectTimeout:     300 * time.Millisecond,
			MaxOpenConnections: 5,
			MaxIdleConnections: 2,
		},
		Redis: config.RedisConfig{
			Address:        "127.0.0.1:1",
			ConnectTimeout: 300 * time.Millisecond,
		},
		HTTPClient: config.HTTPClientConfig{
			Timeout:               time.Second,
			MaxIdleConnections:    10,
			MaxConnectionsPerHost: 10,
			MaxResponseSize:       1024,
			MaxRedirects:          5,
		},
		Logging: config.LoggingConfig{Level: "error", Format: "json"},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if _, err := New(context.Background(), cfg, logger); err == nil {
		t.Fatal("expected New() to fail when the database is unreachable")
	}
}
