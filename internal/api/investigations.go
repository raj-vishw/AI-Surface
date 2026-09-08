package api

// Mirrors frontend/src/types/investigation.ts and
// frontend/src/api/investigations.ts.

import (
	"net/http"
	"time"

	domaininvestigation "ai-recon-platform/internal/domain/investigation"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	"ai-recon-platform/internal/repository/pagination"
)

type investigationDTO struct {
	ID              string     `json:"id"`
	TargetID        string     `json:"targetId"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Status          string     `json:"status"`
	Priority        string     `json:"priority"`
	Severity        string     `json:"severity"`
	Confidence      string     `json:"confidence"`
	CreatedBy       string     `json:"createdBy"`
	AssignedTo      string     `json:"assignedTo"`
	DetectedAt      *time.Time `json:"detectedAt"`
	FirstObservedAt *time.Time `json:"firstObservedAt"`
	LastObservedAt  *time.Time `json:"lastObservedAt"`
	Version         int        `json:"version"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	ClosedAt        *time.Time `json:"closedAt"`
}

func toInvestigationDTO(inv domaininvestigation.Investigation) investigationDTO {
	return investigationDTO{
		ID: inv.ID.String(), TargetID: inv.TargetID.String(), Title: inv.Title, Description: inv.Description,
		Status: string(inv.Status), Priority: string(inv.Priority), Severity: string(inv.Severity), Confidence: string(inv.Confidence),
		CreatedBy: inv.CreatedBy, AssignedTo: inv.AssignedTo,
		DetectedAt: inv.DetectedAt, FirstObservedAt: inv.FirstObservedAt, LastObservedAt: inv.LastObservedAt,
		Version: inv.Version, CreatedAt: inv.CreatedAt, UpdatedAt: inv.UpdatedAt, ClosedAt: inv.ClosedAt,
	}
}

func (h *handler) listInvestigations(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	filter := investigationrepo.ListFilter{
		TargetID: targetID, Status: domaininvestigation.Status(r.URL.Query().Get("status")),
		Pagination: paginationParams(r),
	}
	page, err := h.deps.Investigation.List(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]investigationDTO, 0, len(page.Items))
	for _, inv := range page.Items {
		out = append(out, toInvestigationDTO(inv))
	}
	writeJSON(w, http.StatusOK, pageResponse[investigationDTO]{Items: out, HasMore: page.NextCursor != "", NextCursor: page.NextCursor})
}

func (h *handler) getInvestigation(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	inv, err := h.deps.Investigation.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toInvestigationDTO(inv))
}

type timelineEventDTO struct {
	ID              string    `json:"id"`
	TargetID        string    `json:"targetId"`
	InvestigationID string    `json:"investigationId"`
	Timestamp       time.Time `json:"timestamp"`
	Type            string    `json:"type"`
	SourceType      string    `json:"sourceType"`
	SourceID        *string   `json:"sourceId"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Severity        *string   `json:"severity"`
	Actor           string    `json:"actor"`
	CreatedAt       time.Time `json:"createdAt"`
}

func toTimelineEventDTO(e domaininvestigation.TimelineEvent) timelineEventDTO {
	var sourceID *string
	if e.SourceID != nil {
		s := e.SourceID.String()
		sourceID = &s
	}
	var severity *string
	if e.Severity != "" {
		s := e.Severity
		severity = &s
	}
	return timelineEventDTO{
		ID: e.ID.String(), TargetID: e.TargetID.String(), InvestigationID: e.InvestigationID.String(),
		Timestamp: e.Timestamp, Type: string(e.Type), SourceType: string(e.SourceType), SourceID: sourceID,
		Title: e.Title, Description: e.Description, Severity: severity, Actor: e.Actor, CreatedAt: e.CreatedAt,
	}
}

func (h *handler) getInvestigationTimeline(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	page, err := h.deps.Investigation.Timeline(r.Context(), id, false, pagination.Params{Limit: pagination.MaxLimit})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]timelineEventDTO, 0, len(page.Items))
	for _, e := range page.Items {
		out = append(out, toTimelineEventDTO(e))
	}
	writeJSON(w, http.StatusOK, out)
}

type noteDTO struct {
	ID              string     `json:"id"`
	InvestigationID string     `json:"investigationId"`
	AuthorID        string     `json:"authorId"`
	Content         string     `json:"content"`
	AIGenerated     bool       `json:"aiGenerated"`
	ApprovedBy      *string    `json:"approvedBy"`
	ApprovedAt      *time.Time `json:"approvedAt"`
	CreatedAt       time.Time  `json:"createdAt"`
}

func (h *handler) getInvestigationNotes(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	notes, err := h.deps.Investigation.ListNotes(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]noteDTO, 0, len(notes))
	for _, n := range notes {
		out = append(out, noteDTO{
			ID: n.ID.String(), InvestigationID: n.InvestigationID.String(), AuthorID: n.AuthorID, Content: n.Content,
			AIGenerated: n.AIGenerated, ApprovedBy: n.ApprovedBy, ApprovedAt: n.ApprovedAt, CreatedAt: n.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type hypothesisDTO struct {
	ID              string    `json:"id"`
	InvestigationID string    `json:"investigationId"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Status          string    `json:"status"`
	Confidence      string    `json:"confidence"`
	CreatedBy       string    `json:"createdBy"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func (h *handler) getInvestigationHypotheses(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	hyps, err := h.deps.Investigation.ListHypotheses(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]hypothesisDTO, 0, len(hyps))
	for _, hh := range hyps {
		out = append(out, hypothesisDTO{
			ID: hh.ID.String(), InvestigationID: hh.InvestigationID.String(), Title: hh.Title, Description: hh.Description,
			Status: string(hh.Status), Confidence: string(hh.Confidence), CreatedBy: hh.CreatedBy,
			CreatedAt: hh.CreatedAt, UpdatedAt: hh.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
