package api

// Global search (spec §52) fans out across the entities this backend
// actually models — no dedicated backend search endpoint/index exists
// (a real implementation would add Postgres full-text/trigram search
// server-side; see docs/architecture/overview.md's "Backend Changes
// Required" note) so this does the same bounded per-resource query the
// CLI would need multiple separate commands for, client-side filtered.
// Mirrors frontend/src/api/search.ts's SearchResultGroup shape exactly.

import (
	"net/http"
	"strings"

	assetrepo "ai-recon-platform/internal/repository/asset"
	findingrepo "ai-recon-platform/internal/repository/finding"
	intelrepo "ai-recon-platform/internal/repository/intelligence"
	investigationrepo "ai-recon-platform/internal/repository/investigation"
	rulerepo "ai-recon-platform/internal/repository/rule"
)

type searchResultDTO struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Href     string `json:"href"`
}

type searchResultGroupDTO struct {
	Entity  string            `json:"entity"`
	Label   string            `json:"label"`
	Results []searchResultDTO `json:"results"`
}

const searchLimit = 5

func (h *handler) search(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if q == "" {
		writeJSON(w, http.StatusOK, []searchResultGroupDTO{})
		return
	}
	ctx := r.Context()
	var groups []searchResultGroupDTO

	if assetPage, err := h.deps.Assets.List(ctx, assetrepo.ListFilter{TargetID: targetID, Pagination: pagination500()}); err == nil {
		var results []searchResultDTO
		for _, a := range assetPage.Items {
			name := h.assetDisplayNameOf(a)
			if strings.Contains(strings.ToLower(name), q) {
				results = append(results, searchResultDTO{ID: a.ID.String(), Title: name, Subtitle: string(a.Type), Href: "/assets/" + a.ID.String()})
				if len(results) >= searchLimit {
					break
				}
			}
		}
		if len(results) > 0 {
			groups = append(groups, searchResultGroupDTO{Entity: "assets", Label: "Assets", Results: results})
		}
	}

	if findingPage, err := h.deps.Findings.List(ctx, findingrepo.ListFilter{TargetID: targetID, Pagination: pagination500()}); err == nil {
		var results []searchResultDTO
		for _, f := range findingPage.Items {
			if strings.Contains(strings.ToLower(f.Title), q) {
				results = append(results, searchResultDTO{ID: f.ID.String(), Title: f.Title, Subtitle: string(f.Severity), Href: "/findings/" + f.ID.String()})
				if len(results) >= searchLimit {
					break
				}
			}
		}
		if len(results) > 0 {
			groups = append(groups, searchResultGroupDTO{Entity: "findings", Label: "Findings", Results: results})
		}
	}

	if alertPage, err := h.deps.Rules.ListAlerts(ctx, rulerepo.AlertListFilter{TargetID: targetID, Pagination: pagination500()}); err == nil {
		var results []searchResultDTO
		for _, a := range alertPage.Items {
			if strings.Contains(strings.ToLower(a.Title), q) {
				results = append(results, searchResultDTO{ID: a.ID.String(), Title: a.Title, Subtitle: string(a.Severity), Href: "/alerts"})
				if len(results) >= searchLimit {
					break
				}
			}
		}
		if len(results) > 0 {
			groups = append(groups, searchResultGroupDTO{Entity: "alerts", Label: "Alerts", Results: results})
		}
	}

	if invPage, err := h.deps.Investigation.List(ctx, investigationrepo.ListFilter{TargetID: targetID, Pagination: pagination500()}); err == nil {
		var results []searchResultDTO
		for _, inv := range invPage.Items {
			if strings.Contains(strings.ToLower(inv.Title), q) {
				results = append(results, searchResultDTO{ID: inv.ID.String(), Title: inv.Title, Subtitle: string(inv.Status), Href: "/investigations/" + inv.ID.String()})
				if len(results) >= searchLimit {
					break
				}
			}
		}
		if len(results) > 0 {
			groups = append(groups, searchResultGroupDTO{Entity: "investigations", Label: "Investigations", Results: results})
		}
	}

	if clusterPage, err := h.deps.Investigation.ListClusters(ctx, investigationrepo.ClusterListFilter{TargetID: targetID, Pagination: pagination500()}); err == nil {
		var results []searchResultDTO
		for _, c := range clusterPage.Items {
			if strings.Contains(strings.ToLower(c.Title), q) {
				results = append(results, searchResultDTO{ID: c.ID.String(), Title: c.Title, Subtitle: string(c.Status), Href: "/incidents/" + c.ID.String()})
				if len(results) >= searchLimit {
					break
				}
			}
		}
		if len(results) > 0 {
			groups = append(groups, searchResultGroupDTO{Entity: "incidents", Label: "Incidents", Results: results})
		}
	}

	if intelPage, err := h.deps.IntelRecords.ListRecords(ctx, intelrepo.RecordListFilter{TargetID: targetID, Pagination: pagination500()}); err == nil {
		var results []searchResultDTO
		for _, rec := range intelPage.Items {
			if strings.Contains(strings.ToLower(rec.IndicatorValue), q) {
				results = append(results, searchResultDTO{ID: rec.ID.String(), Title: rec.IndicatorValue, Subtitle: string(rec.IndicatorType), Href: "/intelligence"})
				if len(results) >= searchLimit {
					break
				}
			}
		}
		if len(results) > 0 {
			groups = append(groups, searchResultGroupDTO{Entity: "intelligence", Label: "Intelligence", Results: results})
		}
	}

	if groups == nil {
		groups = []searchResultGroupDTO{}
	}
	writeJSON(w, http.StatusOK, groups)
}
