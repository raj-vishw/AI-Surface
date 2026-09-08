// Package application is the server process's dependency-injection
// container: it owns every long-lived resource (database pool, Redis
// client, HTTP client, HTTP server), brings them up in dependency order,
// and tears them down cleanly. cmd/server is intentionally thin — it just
// calls New, Run, and Close.
//
// Bootstrap order: LoadConfig -> InitializeLogger -> InitializeDatabase ->
// InitializeRedis -> InitializeHTTPClient -> InitializeHealth ->
// InitializeServer. Config and logger are constructed by the caller
// (cmd/server) since every executable needs them before deciding what else
// to initialize; New takes over from InitializeDatabase onward.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"ai-recon-platform/internal/api"
	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/database"
	"ai-recon-platform/internal/health"
	"ai-recon-platform/internal/httpclient"
	"ai-recon-platform/internal/httpserver"
	"ai-recon-platform/internal/redis"
)

// Application holds every resource the server needs for its lifetime.
type Application struct {
	Config *config.Config
	Logger *slog.Logger

	DB         *database.Pool
	Redis      *redis.Client
	HTTPClient *httpclient.Client
	Services   *Services
	Server     *httpserver.Server
}

// New connects to every dependency and assembles the HTTP server. If any
// step fails, resources already connected are closed before the error is
// returned, so callers never receive a partially-initialized Application
// they'd need to clean up themselves.
func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Application, error) {
	db, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	redisClient, err := redis.Connect(ctx, cfg.Redis)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to redis: %w", err)
	}

	httpClient := httpclient.NewFromConfig(cfg.HTTPClient)

	services, err := buildServices(db, cfg, logger)
	if err != nil {
		db.Close()
		if closeErr := redisClient.Close(); closeErr != nil {
			logger.Warn("redis_close_error", "error", closeErr)
		}
		return nil, fmt.Errorf("wiring services: %w", err)
	}

	server := httpserver.New(cfg.Server, logger,
		[]health.Dependency{
			{Name: "database", Checker: db},
			{Name: "redis", Checker: redisClient},
		},
		httpserver.Options{RegisterRoutes: api.NewRouter(services.APIDeps(), logger)},
	)

	return &Application{
		Config:     cfg,
		Logger:     logger,
		DB:         db,
		Redis:      redisClient,
		HTTPClient: httpClient,
		Services:   services,
		Server:     server,
	}, nil
}

// Run starts the HTTP server and blocks until ctx is cancelled (typically
// by a SIGINT/SIGTERM handler installed by the caller), at which point it
// gracefully shuts the server down within Config.Server.ShutdownTimeout.
func (a *Application) Run(ctx context.Context) error {
	serveErrCh := make(chan error, 1)
	go func() {
		a.Logger.Info("server_starting", "addr", a.Server.Addr())
		serveErrCh <- a.Server.ListenAndServe()
	}()

	select {
	case err := <-serveErrCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	case <-ctx.Done():
		a.Logger.Info("shutdown_signal_received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.Config.Server.ShutdownTimeout)
	defer cancel()

	if err := a.Server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down server: %w", err)
	}

	if err := <-serveErrCh; err != nil {
		a.Logger.Warn("server_reported_error_after_shutdown", "error", err)
	}

	a.Logger.Info("server_stopped_cleanly")
	return nil
}

// Close releases every long-lived resource. Callers must invoke it after
// Run returns, regardless of whether Run returned an error.
func (a *Application) Close() {
	if a.Redis != nil {
		if err := a.Redis.Close(); err != nil {
			a.Logger.Warn("redis_close_error", "error", err)
		}
	}
	if a.DB != nil {
		a.DB.Close()
	}
}
