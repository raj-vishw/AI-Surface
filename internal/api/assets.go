package api

// Mirrors frontend/src/types/asset.ts and frontend/src/api/assets.ts.

import (
	"net/http"
	"strings"
	"time"

	domainasset "ai-recon-platform/internal/domain/asset"
	assetrepo "ai-recon-platform/internal/repository/asset"
)

type assetDTO struct {
	ID              string         `json:"id"`
	TargetID        string         `json:"targetId"`
	Type            string         `json:"type"`
	Status          string         `json:"status"`
	Confidence      float64        `json:"confidence"`
	ConfidenceLevel string         `json:"confidenceLevel"`
	Hostname        *string        `json:"hostname"`
	IP              *string        `json:"ip"`
	Port            *int           `json:"port"`
	Protocol        *string        `json:"protocol"`
	URL             *string        `json:"url"`
	Technology      *string        `json:"technology"`
	Provider        *string        `json:"provider"`
	Model           *string        `json:"model"`
	Environment     *string        `json:"environment"`
	Source          string         `json:"source"`
	IdentityKey     string         `json:"identityKey"`
	FirstSeen       time.Time      `json:"firstSeen"`
	LastSeen        time.Time      `json:"lastSeen"`
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
	Metadata        map[string]any `json:"metadata"`
}

func toAssetDTO(a domainasset.Asset) assetDTO {
	return assetDTO{
		ID: a.ID.String(), TargetID: a.TargetID.String(), Type: string(a.Type), Status: string(a.Status),
		Confidence: float64(a.Confidence), ConfidenceLevel: string(a.Confidence.Level()),
		Hostname: a.Hostname, IP: a.IP, Port: a.Port, Protocol: a.Protocol, URL: a.URL,
		Technology: a.Technology, Provider: a.Provider, Model: a.Model, Environment: a.Environment,
		Source: a.Source, IdentityKey: a.IdentityKey,
		FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		Metadata: emptyIfNil(a.Metadata),
	}
}

func emptyIfNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func (h *handler) listAssets(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := assetrepo.ListFilter{
		TargetID:   targetID,
		Type:       domainasset.Type(q.Get("type")),
		Status:     domainasset.Status(q.Get("status")),
		Pagination: paginationParams(r),
	}
	page, err := h.deps.Assets.List(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	items := page.Items
	if search := strings.ToLower(q.Get("search")); search != "" {
		filtered := items[:0]
		for _, a := range items {
			if matchesAssetSearch(a, search) {
				filtered = append(filtered, a)
			}
		}
		items = filtered
	}
	out := make([]assetDTO, 0, len(items))
	for _, a := range items {
		out = append(out, toAssetDTO(a))
	}
	writeJSON(w, http.StatusOK, pageResponse[assetDTO]{Items: out, HasMore: page.NextCursor != "", NextCursor: page.NextCursor})
}

func matchesAssetSearch(a domainasset.Asset, search string) bool {
	for _, f := range []*string{a.Hostname, a.IP, a.URL, a.Technology} {
		if f != nil && strings.Contains(strings.ToLower(*f), search) {
			return true
		}
	}
	return false
}

func (h *handler) getAsset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	a, err := h.deps.Assets.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toAssetDTO(a))
}

func (h *handler) getAssetFingerprints(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	page, err := h.deps.Fingerprints.List(r.Context(), fingerprintListFilter(id))
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]fingerprintDTO, 0, len(page.Items))
	for _, f := range page.Items {
		out = append(out, toFingerprintDTO(f))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getAssetFindings(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	page, err := h.deps.Findings.List(r.Context(), findingListFilterByAsset(id))
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]findingDTO, 0, len(page.Items))
	for _, f := range page.Items {
		out = append(out, toFindingDTO(f, ""))
	}
	writeJSON(w, http.StatusOK, out)
}

// pageResponse is the shared cursor-page JSON envelope every list
// endpoint returns — mirrors frontend/src/types/common.ts's Page<T>
// exactly (no `total`; see that file's doc comment on why).
type pageResponse[T any] struct {
	Items      []T    `json:"items"`
	HasMore    bool   `json:"hasMore"`
	NextCursor string `json:"nextCursor,omitempty"`
}
