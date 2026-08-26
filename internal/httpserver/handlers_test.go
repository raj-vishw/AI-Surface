package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ai-recon-platform/internal/health"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeChecker struct {
	err error
}

func (f fakeChecker) HealthCheck(ctx context.Context) error {
	return f.err
}

func TestHealthHandlerReturnsOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	healthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("expected status \"ok\", got %q", body.Status)
	}
}

func TestReadyHandlerAllHealthy(t *testing.T) {
	deps := []health.Dependency{
		{Name: "database", Checker: fakeChecker{}},
		{Name: "redis", Checker: fakeChecker{}},
	}
	handler := readyHandler(discardLogger(), deps)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body readyResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("expected overall status \"ok\", got %q", body.Status)
	}
	if len(body.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(body.Checks))
	}
	for _, c := range body.Checks {
		if c.Status != "ok" {
			t.Errorf("expected check %q to be ok, got %q", c.Name, c.Status)
		}
	}
}

func TestReadyHandlerUnhealthyDependencyDoesNotLeakInternalError(t *testing.T) {
	deps := []health.Dependency{
		{Name: "database", Checker: fakeChecker{err: errors.New("password authentication failed for user \"admin\"")}},
	}
	handler := readyHandler(discardLogger(), deps)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	raw := rec.Body.String()
	if strings.Contains(raw, "password authentication failed") {
		t.Fatalf("response leaked internal error detail: %s", raw)
	}

	var body readyResponse
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Status != "unavailable" {
		t.Errorf("expected overall status \"unavailable\", got %q", body.Status)
	}
	if len(body.Checks) != 1 || body.Checks[0].Status != "unavailable" || body.Checks[0].Reason != "unreachable" {
		t.Errorf("unexpected check result: %+v", body.Checks)
	}
}

func TestReadyHandlerNoDependencies(t *testing.T) {
	handler := readyHandler(discardLogger(), nil)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 with no dependencies configured, got %d", rec.Code)
	}
}
