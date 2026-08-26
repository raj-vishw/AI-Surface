// Package logging configures the platform's structured (JSON) logger.
//
// The platform standardizes on the standard library's log/slog so that no
// logging dependency is required. Request-scoped loggers are attached to
// context.Context so that a request ID (and future fields such as
// organization ID) automatically appear on every log line for that request.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format controls the output encoding of the logger.
type Format string

// Supported log output formats.
const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// Options configures New.
type Options struct {
	Level  string // debug | info | warn | error
	Format Format
	Output io.Writer // defaults to os.Stdout when nil
}

// New builds a *slog.Logger according to opts. Unknown levels default to
// info; unknown formats default to JSON, since JSON is required for
// production log aggregation.
func New(opts Options) *slog.Logger {
	if opts.Output == nil {
		opts.Output = os.Stdout
	}

	handlerOpts := &slog.HandlerOptions{
		Level: parseLevel(opts.Level),
	}

	var handler slog.Handler
	if opts.Format == FormatText {
		handler = slog.NewTextHandler(opts.Output, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(opts.Output, handlerOpts)
	}

	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type contextKey int

const loggerContextKey contextKey = iota

// WithContext attaches logger to ctx so it can be retrieved via FromContext.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey, logger)
}

// FromContext returns the logger attached to ctx, or fallback if none is
// present. fallback must not be nil.
func FromContext(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if logger, ok := ctx.Value(loggerContextKey).(*slog.Logger); ok && logger != nil {
		return logger
	}
	return fallback
}
