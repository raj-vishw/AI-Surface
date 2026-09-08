package api

// Mirrors frontend/src/types/finding.ts and frontend/src/api/findings.ts.

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	domainasset "ai-recon-platform/internal/domain/asset"
	domainfinding "ai-recon-platform/internal/domain/finding"
	findingrepo "ai-recon-platform/internal/repository/finding"
)

type findingReferenceDTO struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type findingDTO struct {
	ID                     string                `json:"id"`
	TargetID               string                `json:"targetId"`
	AssetID                string                `json:"assetId"`
	EndpointID             *string               `json:"endpointId"`
	ScanID                 *string               `json:"scanId"`
	DetectorID             string                `json:"detectorId"`
	DetectorVersion        int                   `json:"detectorVersion"`
	Title                  string                `json:"title"`
	Description            string                `json:"description"`
	Category               string                `json:"category"`
	Scope                  string                `json:"scope"`
	Severity               string                `json:"severity"`
	DetectorSeverity       string                `json:"detectorSeverity"`
	Confidence             float64               `json:"confidence"`
	Status                 string                `json:"status"`
	Remediation            string                `json:"remediation"`
	References             []findingReferenceDTO `json:"references"`
	SeverityOverridden     bool                  `json:"severityOverridden"`
	SeverityOverrideReason string                `json:"severityOverrideReason"`
	SeverityOverriddenAt   *time.Time            `json:"severityOverriddenAt"`
	SuppressionReason      string                `json:"suppressionReason"`
	FirstSeen              time.Time             `json:"firstSeen"`
	LastSeen               time.Time             `json:"lastSeen"`
	ResolvedAt             *time.Time            `json:"resolvedAt"`
	CreatedAt              time.Time             `json:"createdAt"`
	UpdatedAt              time.Time             `json:"updatedAt"`
	AssetName              string                `json:"assetName,omitempty"`
}

func toFindingDTO(f domainfinding.Finding, assetName string) findingDTO {
	refs := make([]findingReferenceDTO, 0, len(f.References))
	for _, ref := range f.References {
		refs = append(refs, findingReferenceDTO{Label: ref.Label, URL: ref.URL})
	}
	var endpointID *string
	if f.EndpointID != nil {
		s := f.EndpointID.String()
		endpointID = &s
	}
	var scanID *string
	if f.ScanID != nil {
		s := f.ScanID.String()
		scanID = &s
	}
	return findingDTO{
		ID: f.ID.String(), TargetID: f.TargetID.String(), AssetID: f.AssetID.String(),
		EndpointID: endpointID, ScanID: scanID,
		DetectorID: f.DetectorID, DetectorVersion: f.DetectorVersion,
		Title: f.Title, Description: f.Description,
		Category: string(f.Category), Scope: string(f.Scope),
		Severity: string(f.Severity), DetectorSeverity: string(f.DetectorSeverity), Confidence: float64(f.Confidence),
		Status: string(f.Status), Remediation: f.Remediation, References: refs,
		SeverityOverridden: f.SeverityOverridden, SeverityOverrideReason: f.SeverityOverrideReason, SeverityOverriddenAt: f.SeverityOverriddenAt,
		SuppressionReason: f.SuppressionReason,
		FirstSeen:         f.FirstSeen, LastSeen: f.LastSeen, ResolvedAt: f.ResolvedAt,
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt, AssetName: assetName,
	}
}

func findingListFilterByAsset(assetID uuid.UUID) findingrepo.ListFilter {
	return findingrepo.ListFilter{AssetID: assetID, Pagination: pagination500()}
}

func (h *handler) listFindings(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	assetID, err := optionalUUID(r, "assetId")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: errorBody{Category: "validation", Message: "assetId must be a valid UUID"}})
		return
	}
	filter := findingrepo.ListFilter{
		TargetID: targetID, AssetID: assetID,
		Severity:   domainfinding.Severity(q.Get("severity")),
		Status:     domainfinding.Status(q.Get("status")),
		Category:   domainfinding.Category(q.Get("category")),
		Pagination: paginationParams(r),
	}
	page, err := h.deps.Findings.List(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	items := page.Items
	if search := strings.ToLower(q.Get("search")); search != "" {
		filtered := items[:0]
		for _, f := range items {
			if strings.Contains(strings.ToLower(f.Title), search) || strings.Contains(strings.ToLower(f.Description), search) {
				filtered = append(filtered, f)
			}
		}
		items = filtered
	}
	out := make([]findingDTO, 0, len(items))
	for _, f := range items {
		assetName := h.assetDisplayName(r, f.AssetID)
		out = append(out, toFindingDTO(f, assetName))
	}
	writeJSON(w, http.StatusOK, pageResponse[findingDTO]{Items: out, HasMore: page.NextCursor != "", NextCursor: page.NextCursor})
}

func (h *handler) getFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	f, err := h.deps.Findings.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toFindingDTO(f, h.assetDisplayName(r, f.AssetID)))
}

// assetDisplayName resolves an asset's display name for table
// denormalization the same way the mock layer already does — a
// best-effort lookup that degrades to an empty string (never an error)
// since the frontend already falls back to the raw id when this is
// absent (see src/types/asset.ts's assetDisplayName).
func (h *handler) assetDisplayName(r *http.Request, assetID uuid.UUID) string {
	a, err := h.deps.Assets.GetByID(r.Context(), assetID)
	if err != nil {
		return ""
	}
	return h.assetDisplayNameOf(a)
}

// assetDisplayNameOf is the no-lookup variant of assetDisplayName for
// callers that already hold the asset (e.g. a correlation graph node
// resolved via Assets.GetByID once already).
func (h *handler) assetDisplayNameOf(a domainasset.Asset) string {
	switch {
	case a.Hostname != nil:
		return *a.Hostname
	case a.URL != nil:
		return *a.URL
	case a.IP != nil:
		return *a.IP
	default:
		return ""
	}
}
