package httpserver

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"ai-recon-platform/internal/health"
	"ai-recon-platform/internal/version"
)

type errorBody struct {
	Message string `json:"message"`
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:  "ok",
		Version: version.Get().Version,
	})
}

type readyCheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type readyResponse struct {
	Status string             `json:"status"`
	Checks []readyCheckResult `json:"checks"`
}

// readyHandler reports whether every dependency is reachable, using
// internal/health to run the checks. The full error from a failed check is
// logged server-side (it may contain internal connection details) but
// never returned to the client — see health.CheckAll.
func readyHandler(logger *slog.Logger, dependencies []health.Dependency) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := health.CheckAll(r.Context(), logger, dependencies)

		checks := make([]readyCheckResult, 0, len(report.Checks))
		for _, c := range report.Checks {
			checks = append(checks, readyCheckResult{
				Name:   c.Name,
				Status: string(c.Status),
				Reason: c.Reason,
			})
		}

		status := http.StatusOK
		if report.Status != health.StatusOK {
			status = http.StatusServiceUnavailable
		}

		writeJSON(w, status, readyResponse{Status: string(report.Status), Checks: checks})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
