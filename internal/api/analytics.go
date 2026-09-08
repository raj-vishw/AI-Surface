package api

// Mirrors frontend/src/types/analytics.ts and frontend/src/api/analytics.ts.
// Every handler here is a thin pass-through to internal/analytics.Service
// — the JSON shape comes directly from that package's own (now JSON-
// tagged) result structs, not a duplicate DTO, since those structs were
// never part of any other wire contract before this API existed.

import (
	"net/http"
	"time"

	"ai-recon-platform/internal/analytics"
)

// parseRange reads ?range=24h|7d|30d|90d (default 30d, matching the
// frontend's own default) via analytics.ResolveRange, which validates
// the preset and picks the matching interval.
func parseRange(w http.ResponseWriter, r *http.Request) (analytics.TimeRange, bool) {
	preset := r.URL.Query().Get("range")
	if preset == "" {
		preset = "30d"
	}
	tr, err := analytics.ResolveRange(analytics.RangePreset(preset), time.Time{}, time.Time{}, "")
	if err != nil {
		writeError(w, discardLogger{}, err)
		return analytics.TimeRange{}, false
	}
	return tr, true
}

// discardLogger satisfies writeError's logger parameter for the
// validation-error path (a bad ?range= value is never worth an error
// log line — it's the caller's mistake, already reported in the 400
// response body).
type discardLogger struct{}

func (discardLogger) Error(string, ...any) {}

func (h *handler) analyticsOverview(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Overview(r.Context(), targetID)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsRisk(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Risk(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsAlerts(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Alerts(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsDetections(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Detections(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsFindings(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Findings(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsAssets(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Assets(r.Context(), targetID)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsAttackSurface(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.AttackSurface(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsCorrelations(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Correlations(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsInvestigations(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Investigations(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsIntelligence(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Intelligence(r.Context(), targetID)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsAI(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	tr, ok := parseRange(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.AI(r.Context(), targetID, tr)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) analyticsPosture(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	result, err := h.deps.Analytics.Posture(r.Context(), targetID)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
