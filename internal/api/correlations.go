package api

// Mirrors frontend/src/types/correlation.ts and
// frontend/src/api/correlations.ts.

import (
	"net/http"
	"time"

	domaincorrelation "ai-recon-platform/internal/domain/correlation"
	correlationrepo "ai-recon-platform/internal/repository/correlation"
	"ai-recon-platform/internal/repository/pagination"
)

type correlationDTO struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"targetId"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Severity    string    `json:"severity"`
	Confidence  string    `json:"confidence"`
	Score       int       `json:"score"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func toCorrelationDTO(c domaincorrelation.Correlation) correlationDTO {
	return correlationDTO{
		ID: c.ID.String(), TargetID: c.TargetID.String(), Title: c.Title, Description: c.Description,
		Status: string(c.Status), Severity: string(c.Severity), Confidence: string(c.Confidence), Score: c.Score,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

func (h *handler) listCorrelations(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	filter := correlationrepo.ListFilter{
		TargetID: targetID, Status: domaincorrelation.Status(r.URL.Query().Get("status")),
		Pagination: paginationParams(r),
	}
	page, err := h.deps.Correlations.ListCorrelations(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]correlationDTO, 0, len(page.Items))
	for _, c := range page.Items {
		out = append(out, toCorrelationDTO(c))
	}
	writeJSON(w, http.StatusOK, pageResponse[correlationDTO]{Items: out, HasMore: page.NextCursor != "", NextCursor: page.NextCursor})
}

func (h *handler) getCorrelation(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	c, err := h.deps.Correlations.GetCorrelation(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toCorrelationDTO(c))
}

type correlationNodeDTO struct {
	ID            string `json:"id"`
	CorrelationID string `json:"correlationId"`
	Type          string `json:"type"`
	ReferenceID   string `json:"referenceId"`
	Role          string `json:"role"`
	Label         string `json:"label"`
}

type correlationEdgeDTO struct {
	ID            string `json:"id"`
	CorrelationID string `json:"correlationId"`
	SourceNodeID  string `json:"sourceNodeId"`
	TargetNodeID  string `json:"targetNodeId"`
	Relationship  string `json:"relationship"`
	Confidence    string `json:"confidence"`
}

type correlationGraphDTO struct {
	Nodes []correlationNodeDTO `json:"nodes"`
	Edges []correlationEdgeDTO `json:"edges"`
}

// labelForNode resolves a display label for a graph node from its
// referenced entity — a finding's title, an asset's hostname/IP/URL — the
// same denormalization the mock layer already does, never fabricated.
func (h *handler) labelForNode(r *http.Request, n domaincorrelation.Node) string {
	switch n.Type {
	case domaincorrelation.NodeFinding:
		if f, err := h.deps.Findings.GetByID(r.Context(), n.ReferenceID); err == nil {
			return f.Title
		}
	case domaincorrelation.NodeAsset:
		if a, err := h.deps.Assets.GetByID(r.Context(), n.ReferenceID); err == nil {
			return h.assetDisplayNameOf(a)
		}
	}
	return string(n.Type)
}

func (h *handler) getCorrelationGraph(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	nodes, err := h.deps.Correlations.ListNodes(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	edges, err := h.deps.Correlations.ListEdges(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	nodeDTOs := make([]correlationNodeDTO, 0, len(nodes))
	for _, n := range nodes {
		nodeDTOs = append(nodeDTOs, correlationNodeDTO{
			ID: n.ID.String(), CorrelationID: n.CorrelationID.String(), Type: string(n.Type),
			ReferenceID: n.ReferenceID.String(), Role: string(n.Role), Label: h.labelForNode(r, n),
		})
	}
	edgeDTOs := make([]correlationEdgeDTO, 0, len(edges))
	for _, e := range edges {
		edgeDTOs = append(edgeDTOs, correlationEdgeDTO{
			ID: e.ID.String(), CorrelationID: e.CorrelationID.String(), SourceNodeID: e.SourceNodeID.String(),
			TargetNodeID: e.TargetNodeID.String(), Relationship: string(e.Relationship), Confidence: string(e.Confidence),
		})
	}
	writeJSON(w, http.StatusOK, correlationGraphDTO{Nodes: nodeDTOs, Edges: edgeDTOs})
}

type attackChainDTO struct {
	ID            string    `json:"id"`
	CorrelationID string    `json:"correlationId"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Confidence    string    `json:"confidence"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func toAttackChainDTO(c domaincorrelation.AttackChain) attackChainDTO {
	return attackChainDTO{
		ID: c.ID.String(), CorrelationID: c.CorrelationID.String(), Name: c.Name, Description: c.Description,
		Confidence: string(c.Confidence), Severity: string(c.Severity), Status: string(c.Status),
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

// listAttackChains lists every chain for correlations belonging to
// targetID — internal/service/correlation.ListChains has no target
// filter of its own (a chain references a correlation, not a target
// directly), so this filters client-side against the target's own
// correlation ids, the same N-then-filter pattern the mock layer uses.
func (h *handler) listAttackChains(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	correlationPage, err := h.deps.Correlations.ListCorrelations(r.Context(), correlationrepo.ListFilter{TargetID: targetID, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	belongsToTarget := make(map[string]bool, len(correlationPage.Items))
	for _, c := range correlationPage.Items {
		belongsToTarget[c.ID.String()] = true
	}

	chainPage, err := h.deps.Correlations.ListChains(r.Context(), pagination.Params{Limit: pagination.MaxLimit})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]attackChainDTO, 0)
	for _, c := range chainPage.Items {
		if belongsToTarget[c.CorrelationID.String()] {
			out = append(out, toAttackChainDTO(c))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getAttackChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	chain, _, err := h.deps.Correlations.GetChainByID(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toAttackChainDTO(chain))
}

type attackChainStageDTO struct {
	ID            string                      `json:"id"`
	AttackChainID string                      `json:"attackChainId"`
	Stage         string                      `json:"stage"`
	Order         int                         `json:"order"`
	Confidence    string                      `json:"confidence"`
	Evidence      []attackChainEvidenceRefDTO `json:"evidence"`
}

type attackChainEvidenceRefDTO struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (h *handler) getAttackChainStages(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	_, stages, err := h.deps.Correlations.GetChainByID(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]attackChainStageDTO, 0, len(stages))
	for _, s := range stages {
		evidence := make([]attackChainEvidenceRefDTO, 0, len(s.Evidence))
		for _, ev := range s.Evidence {
			evidence = append(evidence, attackChainEvidenceRefDTO{Type: string(ev.NodeType), ID: ev.ReferenceID.String()})
		}
		out = append(out, attackChainStageDTO{
			ID: s.ID.String(), AttackChainID: s.AttackChainID.String(), Stage: string(s.Stage),
			Order: s.Order, Confidence: string(s.Confidence), Evidence: evidence,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
