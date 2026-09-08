package api

// Mirrors frontend/src/types/investigation.ts's IncidentCluster and
// frontend/src/api/incidents.ts. "Incidents" IS an accepted
// IncidentCluster (which becomes an Investigation) — there is no
// separate incidents table (see docs/reporting/reports.md's
// Investigation/Incident consolidation note).

import (
	"net/http"
	"time"

	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
)

type incidentClusterDTO struct {
	ID                      string    `json:"id"`
	TargetID                string    `json:"targetId"`
	Title                   string    `json:"title"`
	Confidence              string    `json:"confidence"`
	Status                  string    `json:"status"`
	AcceptedInvestigationID *string   `json:"acceptedInvestigationId"`
	MemberCount             int       `json:"memberCount"`
	CreatedAt               time.Time `json:"createdAt"`
	UpdatedAt               time.Time `json:"updatedAt"`
}

func (h *handler) toIncidentClusterDTO(r *http.Request, c domaininvestigation.IncidentCluster) incidentClusterDTO {
	var acceptedID *string
	if c.AcceptedInvestigationID != nil {
		s := c.AcceptedInvestigationID.String()
		acceptedID = &s
	}
	memberCount := 0
	if items, err := h.deps.Investigation.ListClusterItems(r.Context(), c.ID); err == nil {
		memberCount = len(items)
	}
	return incidentClusterDTO{
		ID: c.ID.String(), TargetID: c.TargetID.String(), Title: c.Title, Confidence: string(c.Confidence),
		Status: string(c.Status), AcceptedInvestigationID: acceptedID, MemberCount: memberCount,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

func (h *handler) listIncidentClusters(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	filter := investigationrepo.ClusterListFilter{
		TargetID: targetID, Status: domaininvestigation.ClusterStatus(r.URL.Query().Get("status")),
		Pagination: pagination500(),
	}
	page, err := h.deps.Investigation.ListClusters(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]incidentClusterDTO, 0, len(page.Items))
	for _, c := range page.Items {
		out = append(out, h.toIncidentClusterDTO(r, c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getIncidentCluster(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	c, err := h.deps.Investigation.GetCluster(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toIncidentClusterDTO(r, c))
}
