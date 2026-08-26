// Package httpserver assembles the platform's HTTP API server: routing,
// middleware (request ID, structured logging, panic recovery), and the
// /health and /ready endpoints. Later phases add REST resource handlers
// under api/rest without changing this package's shape.
package httpserver

import (
	"context"
	"log/slog"
	"net/http"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/health"
)

// Server wraps http.Server with the platform's standard routing and
// middleware stack.
type Server struct {
	httpServer *http.Server
}

// New builds a Server ready to run via ListenAndServe. dependencies are
// polled by /ready on every request via internal/health.
func New(cfg config.ServerConfig, logger *slog.Logger, dependencies ...health.Dependency) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", readyHandler(logger, dependencies))

	handler := recoveryMiddleware(logger)(
		requestIDMiddleware(logger)(
			loggingMiddleware(logger)(mux),
		),
	)

	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Addr(),
			Handler:           handler,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		},
	}
}

// ListenAndServe starts serving and blocks until the server stops. A clean
// shutdown (triggered by Shutdown) is reported as a nil error, not
// http.ErrServerClosed.
func (s *Server) ListenAndServe() error {
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server: it stops accepting new connections
// and waits for in-flight requests to finish, up to ctx's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the address the server is configured to listen on.
func (s *Server) Addr() string {
	return s.httpServer.Addr
}
