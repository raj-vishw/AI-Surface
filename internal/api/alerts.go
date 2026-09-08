package api

// Mirrors frontend/src/types/detection.ts's Alert and
// frontend/src/api/alerts.ts.

import (
	"encoding/json"
	"net/http"
	"time"

	domainrule "ai-recon-platform/internal/domain/rule"
	rulerepo "ai-recon-platform/internal/repository/rule"
)

type alertDTO struct {
	ID               string    `json:"id"`
	TargetID         string    `json:"targetId"`
	DetectionMatchID string    `json:"detectionMatchId"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	Severity         string    `json:"severity"`
	Confidence       string    `json:"confidence"`
	Status           string    `json:"status"`
	InvestigationID  *string   `json:"investigationId"`
	RuleName         string    `json:"ruleName,omitempty"`
	FirstObservedAt  time.Time `json:"firstObservedAt"`
	LastObservedAt   time.Time `json:"lastObservedAt"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

func (h *handler) toAlertDTO(r *http.Request, a domainrule.Alert) alertDTO {
	var invID *string
	if a.InvestigationID != nil {
		s := a.InvestigationID.String()
		invID = &s
	}
	ruleName := ""
	if match, err := h.deps.Rules.GetMatch(r.Context(), a.DetectionMatchID); err == nil {
		if rl, err := h.deps.Rules.GetRule(r.Context(), match.RuleID); err == nil {
			ruleName = rl.Name
		}
	}
	return alertDTO{
		ID: a.ID.String(), TargetID: a.TargetID.String(), DetectionMatchID: a.DetectionMatchID.String(),
		Title: a.Title, Description: a.Description, Severity: string(a.Severity), Confidence: string(a.Confidence),
		Status: string(a.Status), InvestigationID: invID, RuleName: ruleName,
		FirstObservedAt: a.FirstObservedAt, LastObservedAt: a.LastObservedAt, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
}

func (h *handler) listAlerts(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := rulerepo.AlertListFilter{TargetID: targetID, Status: domainrule.AlertStatus(q.Get("status")), Pagination: paginationParams(r)}
	page, err := h.deps.Rules.ListAlerts(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	severity := q.Get("severity")
	out := make([]alertDTO, 0, len(page.Items))
	for _, a := range page.Items {
		if severity != "" && string(a.Severity) != severity {
			continue
		}
		out = append(out, h.toAlertDTO(r, a))
	}
	writeJSON(w, http.StatusOK, pageResponse[alertDTO]{Items: out, HasMore: page.NextCursor != "", NextCursor: page.NextCursor})
}

type patchAlertRequest struct {
	Status string `json:"status"`
}

// patchAlert dispatches to whichever real Service method matches the
// requested status — never a generic "set status" write, since the rule
// service exposes each lifecycle transition as its own explicit,
// validated action (phase11.md's alert lifecycle). "investigating" maps
// to PromoteToInvestigation — the real backend action closest to what
// the frontend's "Investigate" button means (spec §18) — rather than a
// bare status flip with no such state machine transition backing it.
func (h *handler) patchAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body patchAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Category: "validation", Message: "invalid request body"}})
		return
	}

	const apiActor = "api"
	switch body.Status {
	case "acknowledged":
		if _, err := h.deps.Rules.AcknowledgeAlert(r.Context(), id); err != nil {
			writeError(w, h.logger, err)
			return
		}
	case "resolved":
		if _, err := h.deps.Rules.ResolveAlert(r.Context(), id); err != nil {
			writeError(w, h.logger, err)
			return
		}
	case "suppressed":
		if _, err := h.deps.Rules.SuppressAlert(r.Context(), id, "Dismissed via dashboard", apiActor, 90*24*time.Hour); err != nil {
			writeError(w, h.logger, err)
			return
		}
	case "investigating":
		if _, err := h.deps.Rules.PromoteToInvestigation(r.Context(), id, apiActor); err != nil {
			writeError(w, h.logger, err)
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Category: "validation", Message: "status must be one of acknowledged, resolved, suppressed, investigating"}})
		return
	}

	a, err := h.deps.Rules.GetAlert(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toAlertDTO(r, a))
}
