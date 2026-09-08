package api

// This backend has no separate audit-log table — the investigation
// timeline IS its audit trail (see docs/reporting/reports.md's own
// "Audit report" precedent, established since Phase 9/11/12/13).
// Mirrors frontend/src/api/audit.ts: a target-wide read across every
// investigation's timeline.

import (
	"net/http"

	investigationrepo "ai-recon-platform/internal/repository/investigation"
)

func (h *handler) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	invPage, err := h.deps.Investigation.List(r.Context(), investigationrepo.ListFilter{TargetID: targetID, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}

	var out []timelineEventDTO
	for _, inv := range invPage.Items {
		page, err := h.deps.Investigation.Timeline(r.Context(), inv.ID, true, pagination500())
		if err != nil {
			continue
		}
		for _, e := range page.Items {
			out = append(out, toTimelineEventDTO(e))
		}
	}
	if out == nil {
		out = []timelineEventDTO{}
	}
	writeJSON(w, http.StatusOK, pageResponse[timelineEventDTO]{Items: out, HasMore: false})
}
