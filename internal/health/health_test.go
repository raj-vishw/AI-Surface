package health

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

type fakeChecker struct {
	err error
}

func (f fakeChecker) HealthCheck(ctx context.Context) error {
	return f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCheckAllAllHealthy(t *testing.T) {
	deps := []Dependency{
		{Name: "database", Checker: fakeChecker{}},
		{Name: "redis", Checker: fakeChecker{}},
	}

	report := CheckAll(context.Background(), discardLogger(), deps)

	if report.Status != StatusOK {
		t.Errorf("expected overall status ok, got %s", report.Status)
	}
	if len(report.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(report.Checks))
	}
	for _, c := range report.Checks {
		if c.Status != StatusOK {
			t.Errorf("expected check %q to be ok, got %s", c.Name, c.Status)
		}
	}
}

func TestCheckAllUnhealthyDependencyDoesNotLeakInternalError(t *testing.T) {
	deps := []Dependency{
		{Name: "database", Checker: fakeChecker{err: errors.New("password authentication failed for user \"admin\"")}},
	}

	report := CheckAll(context.Background(), discardLogger(), deps)

	if report.Status != StatusUnavailable {
		t.Errorf("expected overall status unavailable, got %s", report.Status)
	}
	if len(report.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(report.Checks))
	}
	if report.Checks[0].Status != StatusUnavailable {
		t.Errorf("expected check status unavailable, got %s", report.Checks[0].Status)
	}
	if report.Checks[0].Reason != "unreachable" {
		t.Errorf("expected generic reason, got %q", report.Checks[0].Reason)
	}
	if strings.Contains(report.Checks[0].Reason, "password") {
		t.Fatal("report leaked internal error detail")
	}
}

func TestCheckAllNoDependencies(t *testing.T) {
	report := CheckAll(context.Background(), discardLogger(), nil)
	if report.Status != StatusOK {
		t.Errorf("expected status ok with no dependencies, got %s", report.Status)
	}
}

func TestCheckAllPartialFailureMarksOverallUnavailable(t *testing.T) {
	deps := []Dependency{
		{Name: "database", Checker: fakeChecker{}},
		{Name: "redis", Checker: fakeChecker{err: errors.New("connection refused")}},
	}

	report := CheckAll(context.Background(), discardLogger(), deps)

	if report.Status != StatusUnavailable {
		t.Errorf("expected overall status unavailable when any dependency fails, got %s", report.Status)
	}
	if report.Checks[0].Status != StatusOK {
		t.Errorf("expected database check to remain ok, got %s", report.Checks[0].Status)
	}
	if report.Checks[1].Status != StatusUnavailable {
		t.Errorf("expected redis check to be unavailable, got %s", report.Checks[1].Status)
	}
}
