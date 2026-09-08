package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"ai-recon-platform/internal/logging"
)

type contextKey int

const requestIDContextKey contextKey = iota

// RequestIDFromContext returns the request ID attached to ctx by
// requestIDMiddleware, or "" if none is present.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDContextKey).(string)
	return id
}

func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing indicates a broken platform CSPRNG; fall back
		// to a fixed marker rather than letting the request fail entirely.
		return "unavailable"
	}
	return hex.EncodeToString(buf)
}

// requestIDMiddleware ensures every request has an ID (reusing an inbound
// X-Request-ID if present), exposes it on the response header, and attaches
// a logger annotated with it to the request context so every log line for
// this request carries the ID automatically.
func requestIDMiddleware(baseLogger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = newRequestID()
			}
			w.Header().Set("X-Request-ID", requestID)

			ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)
			ctx = logging.WithContext(ctx, baseLogger.With("request_id", requestID))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// statusRecorder captures the status code written by downstream handlers so
// loggingMiddleware can report it after the fact.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// loggingMiddleware logs one structured line per request: method, path,
// status, duration, and (via the context logger set by requestIDMiddleware)
// the request ID.
func loggingMiddleware(fallback *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			logger := logging.FromContext(r.Context(), fallback)
			logger.Info("http_request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

// corsMiddleware implements explicit-allowlist CORS (phase15.md §44 —
// never Access-Control-Allow-Origin: "*"): allowedOrigins is normally the
// deployed frontend's own origin(s) (config: server.allowed_origins /
// AI_RECON_SERVER_ALLOWED_ORIGINS). An empty list (the safe default)
// means no cross-origin browser caller is permitted at all — this
// middleware then does nothing, and a browser's own same-origin policy
// blocks everything, exactly as if this middleware didn't exist.
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type")
				h.Set("Access-Control-Max-Age", "600")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeadersMiddleware sets a baseline of defensive HTTP response
// headers on every response (phase15.md §43) — plain JSON everywhere, no
// HTML rendering, so a strict, single fixed policy is safe with no
// per-route exception:
//
//   - Content-Security-Policy: default-src 'none' — there is nothing on
//     this server for a CSP to permit; every response is JSON, not a page
//     that loads sub-resources.
//   - X-Content-Type-Options: nosniff — stops a browser from trying to
//     reinterpret a JSON response as HTML/script.
//   - Referrer-Policy: no-referrer — nothing here should be echoed back to
//     any link a client might follow afterward.
//   - Permissions-Policy — explicitly denies every browser-mediated
//     capability now standardized under this header.
//   - X-Frame-Options: DENY — redundant with the CSP's frame-ancestors
//     omission on modern browsers, kept for older ones.
//
// CORS is handled separately by corsMiddleware, an explicit allowlist
// (server.allowed_origins) rather than a header set unconditionally here
// — a frontend now exists (see ../../frontend) and needs cross-origin
// access to this API in local development and in any deployment where
// they aren't served from the same origin; "*" is never used
// (phase15.md §44). See docs/security/production-hardening.md.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// recoveryMiddleware converts a panic anywhere downstream into a 500
// response instead of crashing the process, and logs the panic value. It
// must wrap every other middleware so it can catch panics they raise too.
func recoveryMiddleware(fallback *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger := logging.FromContext(r.Context(), fallback)
					logger.Error("panic_recovered", "panic", rec)
					writeJSON(w, http.StatusInternalServerError, errorResponse{
						Error: errorBody{Message: "an internal error occurred"},
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
