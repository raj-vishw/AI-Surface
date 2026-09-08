package api

// Mirrors frontend/src/types/intelligence.ts and
// frontend/src/api/intelligence.ts.

import (
	"net/http"
	"time"

	domainintel "ai-recon-platform/internal/domain/intelligence"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
)

type intelligenceRecordDTO struct {
	ID              string     `json:"id"`
	TargetID        string     `json:"targetId"`
	IndicatorType   string     `json:"indicatorType"`
	IndicatorValue  string     `json:"indicatorValue"`
	ProviderID      string     `json:"providerId"`
	ProviderVersion string     `json:"providerVersion"`
	SourceType      string     `json:"sourceType"`
	Confidence      string     `json:"confidence"`
	Malicious       bool       `json:"malicious"`
	Suspicious      bool       `json:"suspicious"`
	Summary         string     `json:"summary"`
	ObservedAt      time.Time  `json:"observedAt"`
	ExpiresAt       *time.Time `json:"expiresAt"`
	CreatedAt       time.Time  `json:"createdAt"`
}

// summarizeRecord synthesizes a short, human-readable summary from a
// Record's own real fields — internal/domain/intelligence.Record has no
// stored Summary/description field of its own (corrected here after
// inspection; see frontend/src/types/intelligence.ts's matching
// correction), so this derives one from Verdict/Category/SourceType
// rather than inventing a phantom field.
func summarizeRecord(rec domainintel.Record) string {
	verdict := string(rec.Verdict)
	if verdict == "" {
		verdict = "unknown"
	}
	return verdict + " (" + string(rec.Category) + ") via " + rec.SourceType
}

func toIntelligenceRecordDTO(rec domainintel.Record) intelligenceRecordDTO {
	return intelligenceRecordDTO{
		ID: rec.ID.String(), TargetID: rec.TargetID.String(), IndicatorType: string(rec.IndicatorType),
		IndicatorValue: rec.IndicatorValue, ProviderID: rec.ProviderID, ProviderVersion: rec.ProviderVersion,
		SourceType: rec.SourceType, Confidence: string(rec.Confidence),
		Malicious: rec.Verdict == domainintel.VerdictMalicious, Suspicious: rec.Verdict == domainintel.VerdictSuspicious,
		Summary: summarizeRecord(rec), ObservedAt: rec.FirstSeen, ExpiresAt: rec.Expiration, CreatedAt: rec.CreatedAt,
	}
}

func (h *handler) listIntelligence(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := intelrepo.RecordListFilter{
		TargetID: targetID, IndicatorType: domainintel.IndicatorType(q.Get("indicatorType")),
		Pagination: paginationParams(r),
	}
	page, err := h.deps.IntelRecords.ListRecords(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	items := page.Items
	if q.Get("maliciousOnly") == "true" {
		filtered := items[:0]
		for _, rec := range items {
			if rec.Verdict == domainintel.VerdictMalicious {
				filtered = append(filtered, rec)
			}
		}
		items = filtered
	}
	out := make([]intelligenceRecordDTO, 0, len(items))
	for _, rec := range items {
		out = append(out, toIntelligenceRecordDTO(rec))
	}
	writeJSON(w, http.StatusOK, pageResponse[intelligenceRecordDTO]{Items: out, HasMore: page.NextCursor != "", NextCursor: page.NextCursor})
}

type riskScoreDTO struct {
	ID           string          `json:"id"`
	TargetID     string          `json:"targetId"`
	EntityType   string          `json:"entityType"`
	EntityID     string          `json:"entityId"`
	Score        int             `json:"score"`
	Severity     string          `json:"severity"`
	Confidence   string          `json:"confidence"`
	ModelVersion string          `json:"modelVersion"`
	Factors      []riskFactorDTO `json:"factors"`
	Explanation  string          `json:"explanation"`
	CalculatedAt time.Time       `json:"calculatedAt"`
}

type riskFactorDTO struct {
	Name        string `json:"name"`
	Points      int    `json:"points"`
	Description string `json:"description"`
}

// listRiskScores implements the Risk page's "highest-risk assets" list
// via internal/repository/analytics.TopRiskyEntities (added this phase
// — see that package's doc comment) rather than an N+1 per-asset
// GetLatestRiskScore loop.
func (h *handler) listRiskScores(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	entityType := r.URL.Query().Get("entityType")
	entities, err := h.deps.Analytics.TopRiskyEntities(r.Context(), targetID, entityType, 50)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]riskScoreDTO, 0, len(entities))
	for _, e := range entities {
		full, err := h.deps.Intelligence.LatestRisk(r.Context(), domainintel.EntityType(e.EntityType), e.EntityID)
		if err != nil {
			continue
		}
		factors := make([]riskFactorDTO, 0, len(full.Factors))
		for _, f := range full.Factors {
			factors = append(factors, riskFactorDTO{Name: f.Name, Points: f.Points, Description: f.Description})
		}
		out = append(out, riskScoreDTO{
			ID: full.ID.String(), TargetID: full.TargetID.String(), EntityType: string(full.EntityType), EntityID: full.EntityID.String(),
			Score: full.Score, Severity: string(full.Severity), Confidence: string(full.Confidence), ModelVersion: full.ModelVersion,
			Factors: factors, Explanation: full.Explanation, CalculatedAt: full.CalculatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
