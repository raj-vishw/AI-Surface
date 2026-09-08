package api

// Mirrors frontend/src/types/reporting.ts and frontend/src/api/{reports,evidence}.ts.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	domainreporting "ai-recon-platform/internal/domain/reporting"
	reportingrepo "ai-recon-platform/internal/repository/reporting"
)

type reportDTO struct {
	ID            string     `json:"id"`
	TargetID      string     `json:"targetId"`
	ReportType    string     `json:"reportType"`
	SubjectID     *string    `json:"subjectId"`
	Version       int        `json:"version"`
	Title         string     `json:"title"`
	Status        string     `json:"status"`
	ContentHash   string     `json:"contentHash"`
	GeneratedBy   string     `json:"generatedBy"`
	ApprovedBy    *string    `json:"approvedBy"`
	ApprovedAt    *time.Time `json:"approvedAt"`
	ApprovalNotes string     `json:"approvalNotes"`
	CreatedAt     time.Time  `json:"createdAt"`
	GeneratedAt   time.Time  `json:"generatedAt"`
}

func toReportDTO(r domainreporting.Report) reportDTO {
	var subjectID *string
	if r.SubjectID != nil {
		s := r.SubjectID.String()
		subjectID = &s
	}
	return reportDTO{
		ID: r.ID.String(), TargetID: r.TargetID.String(), ReportType: string(r.ReportType), SubjectID: subjectID,
		Version: r.Version, Title: r.Title, Status: string(r.Status), ContentHash: r.ContentHash, GeneratedBy: r.GeneratedBy,
		ApprovedBy: r.ApprovedBy, ApprovedAt: r.ApprovedAt, ApprovalNotes: r.ApprovalNotes,
		CreatedAt: r.CreatedAt, GeneratedAt: r.GeneratedAt,
	}
}

// listReports has no native pagination — Service.ListReports returns a
// plain slice (see internal/service/reporting/lifecycle.go) — so this
// endpoint returns a plain array too rather than a fabricated cursor
// envelope around a slice that never had one.
func (h *handler) listReports(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := reportingrepo.ReportListFilter{
		TargetID: targetID, ReportType: domainreporting.Type(q.Get("reportType")), Status: domainreporting.Status(q.Get("status")),
		Pagination: pagination500(),
	}
	reports, err := h.deps.Reporting.ListReports(r.Context(), filter)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]reportDTO, 0, len(reports))
	for _, rep := range reports {
		out = append(out, toReportDTO(rep))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) getReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	rep, err := h.deps.Reporting.GetReport(r.Context(), id)
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toReportDTO(rep))
}

type evidencePackageDTO struct {
	ID           string    `json:"id"`
	TargetID     string    `json:"targetId"`
	ReportID     string    `json:"reportId"`
	ReportTitle  string    `json:"reportTitle"`
	ItemCount    int       `json:"itemCount"`
	ManifestHash string    `json:"manifestHash"`
	CreatedBy    string    `json:"createdBy"`
	CreatedAt    time.Time `json:"createdAt"`
}

// manifestHash derives a single combined hash for display from a
// package's own per-item hashes (internal/reporting.ItemHash) —
// domainreporting.Package stores no single manifest-hash field itself
// (each Item carries its own hash; see internal/service/reporting/
// evidence.go's GetManifest), so this is a real, reproducible SHA-256
// over the sorted item hashes, computed fresh on read rather than an
// invented stored field. Integrity-only, same as every hash in this
// platform's reporting model — never an authentication mechanism.
func manifestHash(items []domainreporting.Item) string {
	hashes := make([]string, 0, len(items))
	for _, it := range items {
		hashes = append(hashes, it.Hash)
	}
	sum := sha256.Sum256([]byte(strings.Join(hashes, "|")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (h *handler) listEvidencePackages(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	page, err := h.deps.ReportPackages.ListPackages(r.Context(), reportingrepo.PackageListFilter{TargetID: targetID, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]evidencePackageDTO, 0, len(page.Items))
	for _, p := range page.Items {
		reportTitle := ""
		if p.ReportID != nil {
			if rep, err := h.deps.Reporting.GetReport(r.Context(), *p.ReportID); err == nil {
				reportTitle = rep.Title
			}
		}
		items, err := h.deps.Reporting.GetManifest(r.Context(), p.ID)
		if err != nil {
			items = nil
		}
		var reportIDStr string
		if p.ReportID != nil {
			reportIDStr = p.ReportID.String()
		}
		out = append(out, evidencePackageDTO{
			ID: p.ID.String(), TargetID: p.TargetID.String(), ReportID: reportIDStr, ReportTitle: reportTitle,
			ItemCount: len(items), ManifestHash: manifestHash(items), CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type controlEvidenceDTO struct {
	ID           string    `json:"id"`
	TargetID     string    `json:"targetId"`
	ControlID    string    `json:"controlId"`
	EvidenceType string    `json:"evidenceType"`
	ReferenceID  string    `json:"referenceId"`
	Description  string    `json:"description"`
	CollectedAt  time.Time `json:"collectedAt"`
}

func (h *handler) listControlEvidence(w http.ResponseWriter, r *http.Request) {
	targetID, ok := requiredTargetID(w, r)
	if !ok {
		return
	}
	records, err := h.deps.Reporting.ListControlEvidence(r.Context(), reportingrepo.ControlEvidenceListFilter{TargetID: targetID, Pagination: pagination500()})
	if err != nil {
		writeError(w, h.logger, err)
		return
	}
	out := make([]controlEvidenceDTO, 0, len(records))
	for _, c := range records {
		out = append(out, controlEvidenceDTO{
			ID: c.ID.String(), TargetID: c.TargetID.String(), ControlID: c.ControlID, EvidenceType: string(c.EvidenceType),
			ReferenceID: c.ReferenceID.String(), Description: c.Description, CollectedAt: c.CollectedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
