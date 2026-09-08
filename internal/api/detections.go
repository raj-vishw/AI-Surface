package api

// Mirrors frontend/src/types/detection.ts and frontend/src/api/detections.ts.

import (
	"net/http"
	"time"

	domainrule "ai-recon-platform/internal/domain/rule"
	rulerepo "ai-recon-platform/internal/repository/rule"
)

// ruleDTO deliberately has no "version" field: internal/domain/rule.Rule
// doesn't carry a current-version number itself (versioning is tracked
// separately via rule.Version rows / Service.GetVersion/ListVersions —
// fetching the latest per rule would mean an extra query per list row,
// not worth it for a listing endpoint) — see frontend/src/types/
// detection.ts's matching correction.
type ruleDTO struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"targetId"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Severity    string    `json:"severity"`
	Confidence  string    `json:"confidence"`
	RuleType    string    `json:"ruleType"`
	Category    string    `json:"category"`
	Tags        []string  `json:"tags"`
	CreatedBy   string    `json:"createdBy"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func toRuleDTO(r domainrule.Rule) ruleDTO {
	return ruleDTO{
		ID: r.ID.String(), TargetID: r.TargetID.String(), Name: r.Name, Description: r.Description,
		Status: string(r.Status), Severity: string(r.Severity), Confidence: string(r.Confidence),
		RuleType: string(r.RuleType), Category: r.Category, Tags: emptyIfNilStrings(r.Tags),
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func emptyIfNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type matchDTO struct {
	ID              string    `json:"id"`
	TargetID        string    `json:"targetId"`
	RuleID          string    `json:"ruleId"`
	RuleVersion     int       `json:"ruleVersion"`
	RuleName        string    `json:"ruleName,omitempty"`
	Status          string    `json:"status"`
	Fingerprint     string    `json:"fingerprint"`
	FirstObservedAt time.Time `json:"firstObservedAt"`
	LastObservedAt  time.Time `json:"lastObservedAt"`
	CreatedAt       time.Time `json:"createdAt"`
}

func toMatchDTO(m domainrule.DetectionMatch, ruleName string) matchDTO {
	return matchDTO{
		ID: m.ID.String(), TargetID: m.TargetID.String(), RuleID: m.RuleID.String(), RuleVersion: m.RuleVersion,
		RuleName: ruleName, Status: string(m.Status), Fingerprint: m.Fingerprint,
		FirstObservedAt: m.FirstObservedAt, LastObservedAt: m.LastObservedAt, CreatedAt: m.CreatedAt,
	}
}

func (h *handler) listRules(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	filter := rulerepo.ListFilter{TargetID: targetID, Status: domainrule.Status(r.URL.Query().Get("status")), Pagination: pagination500()}
	page, err := h.deps.Rules.ListRules(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]ruleDTO, 0, len(page.Items))
	for _, rl := range page.Items {
		out = append(out, toRuleDTO(rl))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	rl, err := h.deps.Rules.GetRule(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toRuleDTO(rl))
}

func (h *handler) listDetectionMatches(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	page, err := h.deps.Rules.ListMatches(r.Context(), rulerepo.MatchListFilter{TargetID: targetID, Pagination: paginationParams(r)})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]matchDTO, 0, len(page.Items))
	for _, m := range page.Items {
		ruleName := ""
		if rl, err := h.deps.Rules.GetRule(r.Context(), m.RuleID); err == nil {
			ruleName = rl.Name
		}
		out = append(out, toMatchDTO(m, ruleName))
	}
	writeJSON(w, http.StatusOK, pageResponse[matchDTO]{Items: out, HasMore: page.NextCursor != "", NextCursor: page.NextCursor})
}
