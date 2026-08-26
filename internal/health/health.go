// Package health implements the platform's liveness/readiness model.
//
// Liveness (is the process alive) and readiness (are required
// dependencies reachable) are deliberately different checks: a process can
// be alive but not ready (e.g. Postgres is down), and callers such as
// load balancers or orchestrators must be able to distinguish the two.
package health

import (
	"context"
	"log/slog"
	"time"
)

// Status is the outcome of a single check, or of a Report as a whole.
type Status string

// Recognized statuses for a single Check or an aggregate Report.
const (
	StatusOK          Status = "ok"
	StatusUnavailable Status = "unavailable"
)

// Checker is implemented by anything readiness should verify — e.g. a
// database pool or cache client.
type Checker interface {
	HealthCheck(ctx context.Context) error
}

// Dependency names a Checker for reporting.
type Dependency struct {
	Name    string
	Checker Checker
}

// Check is the outcome of checking a single Dependency. Reason is a safe,
// non-leaking description — the underlying error (which may contain
// connection details) is logged separately, never returned here.
type Check struct {
	Name   string
	Status Status
	Reason string
}

// Report aggregates every Check into an overall Status.
type Report struct {
	Status Status
	Checks []Check
}

// defaultTimeout bounds how long CheckAll waits on all dependency checks
// combined, so a hung dependency cannot hang readiness indefinitely.
const defaultTimeout = 5 * time.Second

// CheckAll runs every dependency's HealthCheck and aggregates the results.
// Failures are logged (with the real error) via logger but never included
// in the returned Report, which only ever carries the safe reason
// "unreachable" — internal connection errors must not reach API clients.
func CheckAll(ctx context.Context, logger *slog.Logger, dependencies []Dependency) Report {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	checks := make([]Check, 0, len(dependencies))
	overall := StatusOK

	for _, dep := range dependencies {
		check := Check{Name: dep.Name, Status: StatusOK}
		if err := dep.Checker.HealthCheck(ctx); err != nil {
			if logger != nil {
				logger.Error("readiness_check_failed", "dependency", dep.Name, "error", err)
			}
			check.Status = StatusUnavailable
			check.Reason = "unreachable"
			overall = StatusUnavailable
		}
		checks = append(checks, check)
	}

	return Report{Status: overall, Checks: checks}
}
