package api

// Mirrors frontend/src/types/target.ts and frontend/src/api/targets.ts.

import (
	"net/http"
	"time"

	domaintarget "ai-recon-platform/internal/domain/target"
	"ai-recon-platform/internal/repository/pagination"
	targetrepo "ai-recon-platform/internal/repository/target"
)

type targetDTO struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Type                string    `json:"type"`
	Value               string    `json:"value"`
	Description         string    `json:"description"`
	AuthorizationStatus string    `json:"authorizationStatus"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

func toTargetDTO(t domaintarget.Target) targetDTO {
	return targetDTO{
		ID: t.ID.String(), Name: t.Name, Type: string(t.Type), Value: t.Value,
		Description: t.Description, AuthorizationStatus: string(t.AuthorizationStatus),
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}

func (h *handler) listTargets(w http.ResponseWriter, r *http.Request) {
	page, err := h.deps.Targets.List(r.Context(), targetrepo.ListFilter{Pagination: pagination.Params{Limit: 200}})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]targetDTO, 0, len(page.Items))
	for _, t := range page.Items {
		out = append(out, toTargetDTO(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	t, err := h.deps.Targets.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toTargetDTO(t))
}
