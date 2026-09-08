package api

// Mirrors frontend/src/types/ai.ts and frontend/src/api/ai.ts.

import (
	"encoding/json"
	"net/http"
	"time"

	domainai "ai-recon-platform/internal/domain/ai"
	airepo "ai-recon-platform/internal/repository/ai"
)

type aiSessionDTO struct {
	ID              string    `json:"id"`
	TargetID        string    `json:"targetId"`
	InvestigationID *string   `json:"investigationId"`
	UserID          string    `json:"userId"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func toSessionDTO(s domainai.Session) aiSessionDTO {
	var invID *string
	if s.InvestigationID != nil {
		v := s.InvestigationID.String()
		invID = &v
	}
	return aiSessionDTO{ID: s.ID.String(), TargetID: s.TargetID.String(), InvestigationID: invID, UserID: s.UserID, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}
}

func (h *handler) listAISessions(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	page, err := h.deps.AI.ListSessions(r.Context(), airepo.SessionListFilter{TargetID: targetID, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]aiSessionDTO, 0, len(page.Items))
	for _, s := range page.Items {
		out = append(out, toSessionDTO(s))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getAISession(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	s, err := h.deps.AI.GetSession(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toSessionDTO(s))
}

type aiMessageDTO struct {
	ID        string    `json:"id"`
	SessionID string    `json:"sessionId"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"createdAt"`
}

func toMessageDTO(m domainai.Message) aiMessageDTO {
	return aiMessageDTO{ID: m.ID.String(), SessionID: m.SessionID.String(), Role: string(m.Role), Content: m.Content, CreatedAt: m.CreatedAt}
}

func (h *handler) getSessionMessages(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	messages, err := h.deps.AI.ListMessages(r.Context(), id, 0)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]aiMessageDTO, 0, len(messages))
	for _, m := range messages {
		out = append(out, toMessageDTO(m))
	}
	writeJSON(w, http.StatusOK, out)
}

type postMessageRequest struct {
	Content string `json:"content"`
}

// postSessionMessage calls Service.Chat, which persists the analyst's
// question, runs the configured AI provider, and persists+returns the
// assistant's reply — no separate "create message" step exists or is
// needed. If AI is disabled/misconfigured, Chat returns an error, which
// is surfaced as a normal API error, not silently swallowed.
func (h *handler) postSessionMessage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body postMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Category: "validation", Message: "invalid request body"}})
		return
	}
	reply, err := h.deps.AI.Chat(r.Context(), id, body.Content, "")
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toMessageDTO(reply))
}

type aiToolCallDTO struct {
	ID            string         `json:"id"`
	SessionID     *string        `json:"sessionId"`
	RequestID     *string        `json:"requestId"`
	TargetID      string         `json:"targetId"`
	Tool          string         `json:"tool"`
	Arguments     map[string]any `json:"arguments"`
	ResultStatus  string         `json:"resultStatus"`
	ResultSummary string         `json:"resultSummary"`
	CreatedAt     time.Time      `json:"createdAt"`
}

func (h *handler) getSessionToolCalls(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	page, err := h.deps.AIToolCalls.ListToolCalls(r.Context(), airepo.ToolCallListFilter{SessionID: id, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]aiToolCallDTO, 0, len(page.Items))
	for _, c := range page.Items {
		var sessionID, requestID *string
		if c.SessionID != nil {
			v := c.SessionID.String()
			sessionID = &v
		}
		if c.RequestID != nil {
			v := c.RequestID.String()
			requestID = &v
		}
		out = append(out, aiToolCallDTO{
			ID: c.ID.String(), SessionID: sessionID, RequestID: requestID, TargetID: c.TargetID.String(),
			Tool: c.Tool, Arguments: emptyIfNil(c.Arguments), ResultStatus: string(c.ResultStatus),
			ResultSummary: c.ResultSummary, CreatedAt: c.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type aiStructuredResultDTO struct {
	Summary      string   `json:"summary"`
	Observed     []string `json:"observed"`
	Inferred     []string `json:"inferred"`
	Unknown      []string `json:"unknown"`
	EvidenceGaps []string `json:"evidenceGaps"`
	NextSteps    []string `json:"nextSteps"`
	Questions    []string `json:"questions"`
	Citations    []string `json:"citations"`
}

type aiResultDTO struct {
	ID                         string                `json:"id"`
	SessionID                  *string               `json:"sessionId"`
	TaskType                   string                `json:"taskType"`
	Content                    string                `json:"content"`
	Structured                 aiStructuredResultDTO `json:"structured"`
	Provider                   string                `json:"provider"`
	Model                      string                `json:"model"`
	Confidence                 string                `json:"confidence"`
	Citations                  []string              `json:"citations"`
	FabricatedCitationsRemoved []string              `json:"fabricatedCitationsRemoved"`
	UnsupportedClaimsRewritten int                   `json:"unsupportedClaimsRewritten"`
	AttributionRejected        bool                  `json:"attributionRejected"`
	Truncated                  bool                  `json:"truncated"`
	InputTokens                int                   `json:"inputTokens"`
	OutputTokens               int                   `json:"outputTokens"`
	LatencyMS                  int64                 `json:"latencyMs"`
	CreatedAt                  time.Time             `json:"createdAt"`
}

// getSessionResult reconstructs the frontend's AIResult from this
// session's most recent Request/Response audit pair — there is no
// separate "result" entity; Request+Response together ARE the audit
// trail internal/service/ai.persistTaskAudit writes after every task
// (see internal/service/ai/tasks.go). 404s (via the same not-found the
// repository already returns) if this session has no completed task yet.
func (h *handler) getSessionResult(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	reqPage, err := h.deps.AIRequests.ListRequests(r.Context(), airepo.RequestListFilter{SessionID: sessionID, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	if len(reqPage.Items) == 0 {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: errorBody{Category: "not_found", Message: "no AI result exists yet for this session"}})
		return
	}
	latest := reqPage.Items[0]
	for _, req := range reqPage.Items {
		if req.CreatedAt.After(latest.CreatedAt) {
			latest = req
		}
	}
	resp, err := h.deps.AIResponses.GetResponseByRequestID(r.Context(), latest.ID)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}

	structured := aiStructuredResultDTO{}
	if raw, err := json.Marshal(resp.Structured); err == nil {
		_ = json.Unmarshal(raw, &structured)
	}

	var sessionIDPtr *string
	if latest.SessionID != nil {
		v := latest.SessionID.String()
		sessionIDPtr = &v
	}
	// FabricatedCitationsRemoved/UnsupportedClaimsRewritten/
	// AttributionRejected/Truncated are internal/ai.Result's own
	// in-memory guardrail-activity fields (phase13.md §53/§96) —
	// domainai.Response never persists them (only Content/Citations/
	// Confidence/etc. are stored), so a result fetched back later here
	// cannot reconstruct them and defaults to "nothing flagged" rather
	// than inventing a value. The guardrails themselves still ran at
	// generation time either way (see internal/ai.ValidateOutput) — this
	// is a gap in what's *persisted for later reading*, not in what's
	// *enforced*.
	writeJSON(w, http.StatusOK, aiResultDTO{
		ID: resp.ID.String(), SessionID: sessionIDPtr, TaskType: string(latest.TaskType), Content: resp.Content,
		Structured: structured, Provider: resp.Provider, Model: resp.Model, Confidence: string(resp.Confidence),
		Citations: emptyIfNilStrings(resp.Citations), FabricatedCitationsRemoved: []string{}, UnsupportedClaimsRewritten: 0,
		AttributionRejected: false, Truncated: false,
		InputTokens: resp.InputTokens, OutputTokens: resp.OutputTokens, LatencyMS: resp.LatencyMS, CreatedAt: resp.CreatedAt,
	})
}
