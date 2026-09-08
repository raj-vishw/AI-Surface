package api

// Mirrors frontend/src/types/fingerprint.ts and frontend/src/api/fingerprints.ts.

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	domainfinding "ai-recon-platform/internal/domain/finding"
	domainfingerprint "ai-recon-platform/internal/domain/fingerprint"
	findingrepo "ai-recon-platform/internal/repository/finding"
	fingerprintrepo "ai-recon-platform/internal/repository/fingerprint"
)

type fingerprintDTO struct {
	ID         string    `json:"id"`
	AssetID    string    `json:"assetId"`
	TargetID   string    `json:"targetId"`
	Category   string    `json:"category"`
	Technology string    `json:"technology"`
	Product    string    `json:"product"`
	Vendor     string    `json:"vendor"`
	Version    string    `json:"version"`
	Confidence float64   `json:"confidence"`
	Status     string    `json:"status"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
}

func toFingerprintDTO(f domainfingerprint.Fingerprint) fingerprintDTO {
	return fingerprintDTO{
		ID: f.ID.String(), AssetID: f.AssetID.String(), TargetID: f.TargetID.String(),
		Category: string(f.Category), Technology: f.Technology, Product: f.Product, Vendor: f.Vendor, Version: f.Version,
		Confidence: float64(f.Confidence), Status: string(f.Status),
		FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
	}
}

func fingerprintListFilter(assetID uuid.UUID) fingerprintrepo.ListFilter {
	return fingerprintrepo.ListFilter{AssetID: assetID, Pagination: pagination500()}
}

type technologySummaryDTO struct {
	Technology         string    `json:"technology"`
	Category           string    `json:"category"`
	Versions           []string  `json:"versions"`
	AffectedAssetCount int       `json:"affectedAssetCount"`
	CriticalFindings   int       `json:"criticalFindings"`
	FirstSeen          time.Time `json:"firstSeen"`
	LastSeen           time.Time `json:"lastSeen"`
}

// listTechnologies implements frontend/src/api/fingerprints.ts's rollup:
// group every currently-active Fingerprint for the target by technology
// name, counting affected assets and open critical/high findings on
// each. Fingerprint.Status is only ACTIVE/INACTIVE (confirmed by
// inspection — corrected here from an earlier, invented added/confirmed/
// changed/removed lifecycle guessed before this API existed; see
// frontend/src/types/fingerprint.ts's matching correction).
func (h *handler) listTechnologies(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	page, err := h.deps.Fingerprints.List(r.Context(), fingerprintrepo.ListFilter{TargetID: targetID, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}

	type accumulator struct {
		dto      technologySummaryDTO
		versions map[string]bool
	}
	byTech := make(map[string]*accumulator)
	var order []string

	for _, fp := range page.Items {
		if fp.Status != domainfingerprint.StatusActive {
			continue
		}
		acc, exists := byTech[fp.Technology]
		if !exists {
			acc = &accumulator{
				dto:      technologySummaryDTO{Technology: fp.Technology, Category: string(fp.Category), FirstSeen: fp.FirstSeen, LastSeen: fp.LastSeen},
				versions: map[string]bool{},
			}
			byTech[fp.Technology] = acc
			order = append(order, fp.Technology)
		}
		acc.dto.AffectedAssetCount++
		if fp.Version != "" {
			acc.versions[fp.Version] = true
		}
		if fp.FirstSeen.Before(acc.dto.FirstSeen) {
			acc.dto.FirstSeen = fp.FirstSeen
		}
		if fp.LastSeen.After(acc.dto.LastSeen) {
			acc.dto.LastSeen = fp.LastSeen
		}

		findingsPage, err := h.deps.Findings.List(r.Context(), findingrepo.ListFilter{AssetID: fp.AssetID, Status: domainfinding.StatusOpen, Pagination: pagination500()})
		if err == nil {
			for _, f := range findingsPage.Items {
				if f.Severity == domainfinding.SeverityCritical || f.Severity == domainfinding.SeverityHigh {
					acc.dto.CriticalFindings++
				}
			}
		}
	}

	out := make([]technologySummaryDTO, 0, len(order))
	for _, name := range order {
		acc := byTech[name]
		versions := make([]string, 0, len(acc.versions))
		for v := range acc.versions {
			versions = append(versions, v)
		}
		acc.dto.Versions = versions
		out = append(out, acc.dto)
	}
	writeJSON(w, http.StatusOK, out)
}
