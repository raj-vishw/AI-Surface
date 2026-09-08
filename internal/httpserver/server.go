// Package httpserver assembles the platform's HTTP API server: routing,
// middleware (request ID, structured logging, panic recovery), and the
// /health and /ready endpoints. internal/api registers its REST resource
// handlers onto the same mux via the RegisterRoutes option — this
// package's own shape (middleware stack, health endpoints) is unchanged
// by that addition.
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

// Options configures New beyond the required config/logger/dependencies.
type Options struct {
	// RegisterRoutes, if non-nil, is called with the server's mux before
	// any middleware is attached — internal/api uses this to add its REST
	// resource routes alongside /health, /live, and /ready without this
	// package needing to know anything about them.
	RegisterRoutes func(*http.ServeMux)
}

// New builds a Server ready to run via ListenAndServe. dependencies are
// polled by /ready on every request via internal/health.
func New(cfg config.ServerConfig, logger *slog.Logger, dependencies []health.Dependency, opts Options) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	// /live is an alias for /health (phase15.md §25's explicit "/live"
	// liveness endpoint name) — both report "is the process alive", never
	// checking dependencies; /ready is the separate dependency check.
	mux.HandleFunc("GET /live", healthHandler)
	mux.HandleFunc("GET /ready", readyHandler(logger, dependencies))

	if opts.RegisterRoutes != nil {
		opts.RegisterRoutes(mux)
	}

	handler := recoveryMiddleware(logger)(
		requestIDMiddleware(logger)(
			securityHeadersMiddleware(
				corsMiddleware(cfg.AllowedOrigins)(
					loggingMiddleware(logger)(mux),
				),
			),
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
