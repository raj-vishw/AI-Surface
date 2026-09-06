package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ai-recon-platform/internal/config"
	"ai-recon-platform/internal/health"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testServerConfig() config.ServerConfig {
	return config.ServerConfig{Host: "127.0.0.1", Port: 0}
}

type fakeChecker struct{ err error }

func (f fakeChecker) HealthCheck(context.Context) error { return f.err }

func TestServer_SecurityHeadersOnEveryResponse(t *testing.T) {
	srv := New(testServerConfig(), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	want := map[string]string{
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
	}
	for header, expected := range want {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("header %s = %q, want %q", header, got, expected)
		}
	}
}

func TestServer_LiveIsAliasForHealth(t *testing.T) {
	srv := New(testServerConfig(), discardLogger())

	for _, path := range []string{"/health", "/live"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, rec.Code)
		}
	}
}

func TestServer_ReadyReflectsDependencyFailure_WithoutLeakingError(t *testing.T) {
	sensitive := errors.New("dial tcp 10.0.0.5:5432: connection refused (password=hunter2)")
	srv := New(testServerConfig(), discardLogger(),
		health.Dependency{Name: "database", Checker: fakeChecker{err: sensitive}},
	)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	body := rec.Body.String()
	if want := "unreachable"; !strings.Contains(body, want) {
		t.Errorf("response body %q does not contain safe reason %q", body, want)
	}
	if strings.Contains(body, "hunter2") || strings.Contains(body, "10.0.0.5") {
		t.Errorf("response body leaked internal error detail: %q", body)
	}
}

func TestServer_RequestIDEchoedAndGenerated(t *testing.T) {
	srv := New(testServerConfig(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "caller-supplied-id")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-ID"); got != "caller-supplied-id" {
		t.Errorf("X-Request-ID = %q, want echoed caller value", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("X-Request-ID"); got == "" {
		t.Error("X-Request-ID: expected a generated value, got empty")
	}
}

func TestServer_PanicIsRecoveredAsInternalError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) {
		panic("simulated handler panic")
	})
	handler := recoveryMiddleware(discardLogger())(mux)

	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "simulated handler panic") {
		t.Error("panic value leaked into response body")
	}
}
