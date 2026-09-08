package analytics

import (
	"context"

	"github.com/google/uuid"
)

// Overview is the Executive/SOC dashboards' shared summary
// (phase14.md §4/§25) — a single call assembling every headline number
// so a caller never has to make a dozen separate requests just to render
// one landing page (phase14.md §3: "the backend should provide
// appropriate aggregates").
type Overview struct {
	TotalAssets          int `json:"totalAssets"`
	MonitoredAssets      int `json:"monitoredAssets"` // assets with status ACTIVE
	OpenFindings         int `json:"openFindings"`
	OpenAlerts           int `json:"openAlerts"`
	ActiveInvestigations int `json:"activeInvestigations"`
	CriticalRiskAssets   int `json:"criticalRiskAssets"`
	HighRiskAssets       int `json:"highRiskAssets"`
	OpenCorrelations     int `json:"openCorrelations"`
	IntelligenceRecords  int `json:"intelligenceRecords"`
}

// Overview implements phase14.md §4's executive dashboard summary.
// Filters are not applied here — this is deliberately the unfiltered,
// current-state headline view; every other Service method accepts
// Filters for a scoped breakdown.
func (s *Service) Overview(ctx context.Context, targetID uuid.UUID) (Overview, error) {
	return cached(s, targetID, "overview", TimeRange{}, Filters{}, func() (Overview, error) {
		var o Overview
		var err error

		if o.TotalAssets, err = s.repo.CountAssets(ctx, targetID); err != nil {
			return Overview{}, err
		}
		statuses, err := s.repo.CountAssetsByStatus(ctx, targetID)
		if err != nil {
			return Overview{}, err
		}
		for _, sc := range statuses {
			if sc.Name == "ACTIVE" {
				o.MonitoredAssets = sc.Count
			}
		}
		if o.OpenFindings, err = s.repo.CountOpenFindings(ctx, targetID); err != nil {
			return Overview{}, err
		}
		if o.OpenAlerts, err = s.repo.CountOpenAlerts(ctx, targetID); err != nil {
			return Overview{}, err
		}
		if o.ActiveInvestigations, err = s.repo.CountActiveInvestigations(ctx, targetID); err != nil {
			return Overview{}, err
		}
		if o.CriticalRiskAssets, o.HighRiskAssets, err = s.repo.CountCriticalHighRiskAssets(ctx, targetID); err != nil {
			return Overview{}, err
		}
		if o.OpenCorrelations, err = s.repo.CountOpenCorrelations(ctx, targetID); err != nil {
			return Overview{}, err
		}
		if o.IntelligenceRecords, err = s.repo.CountIntelligenceRecords(ctx, targetID); err != nil {
			return Overview{}, err
		}
		return o, nil
	})
}
