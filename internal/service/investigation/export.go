package investigation

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	investigationrepo "ai-surface-platform/internal/repository/investigation"
	"ai-surface-platform/internal/repository/pagination"
)

// ExportFormat names a supported investigation export format (phase9.md
// §59).
type ExportFormat string

// Recognized export formats.
const (
	ExportJSON     ExportFormat = "json"
	ExportCSV      ExportFormat = "csv"
	ExportMarkdown ExportFormat = "markdown"
)

// ExportBundle is everything an investigation export contains (phase9.md
// §59) — findings, evidence references, timeline, relationships,
// hypotheses, notes. Never a raw secret: every field here is already
// redacted by the layer that originally persisted it (Phase 8's
// SanitizeMetadata boundary for findings, and this package's own domain
// types, which never carry a credential field at all).
type ExportBundle struct {
	Summary       Summary
	Findings      []exportFinding
	Evidence      []exportEvidence
	Timeline      []exportTimelineEvent
	Relationships []exportRelationship
	Hypotheses    []exportHypothesis
	Notes         []exportNote
}

type exportFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}
type exportEvidence struct {
	SourceType string `json:"source_type"`
	SourceID   string `json:"source_id"`
	ObservedAt string `json:"observed_at"`
}
type exportTimelineEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Title     string `json:"title"`
}
type exportRelationship struct {
	Type        string `json:"type"`
	Status      string `json:"status"`
	Score       int    `json:"score"`
	Explanation string `json:"explanation"`
}
type exportHypothesis struct {
	Title  string `json:"title"`
	Status string `json:"status"`
}
type exportNote struct {
	AuthorID  string `json:"author_id"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
}

// BuildExportBundle assembles everything Export needs, purely from
// already-persisted rows.
func (s *Service) BuildExportBundle(ctx context.Context, investigationID uuid.UUID) (ExportBundle, error) {
	summary, err := s.Summarize(ctx, investigationID)
	if err != nil {
		return ExportBundle{}, err
	}
	findings, err := s.ListFindings(ctx, investigationID)
	if err != nil {
		return ExportBundle{}, err
	}
	evidencePage, err := s.evidence.ListEvidence(ctx, investigationrepo.EvidenceListFilter{InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		return ExportBundle{}, err
	}
	timelinePage, err := s.timeline.ListTimeline(ctx, investigationrepo.TimelineListFilter{InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		return ExportBundle{}, err
	}
	relPage, err := s.relationships.ListRelationships(ctx, investigationrepo.RelationshipListFilter{InvestigationID: investigationID, Pagination: pagination.Params{Limit: pagination.MaxLimit}})
	if err != nil {
		return ExportBundle{}, err
	}
	hyps, err := s.hypotheses.ListHypotheses(ctx, investigationID)
	if err != nil {
		return ExportBundle{}, err
	}
	notes, err := s.notes.ListNotes(ctx, investigationID)
	if err != nil {
		return ExportBundle{}, err
	}

	bundle := ExportBundle{Summary: summary}
	for _, f := range findings {
		bundle.Findings = append(bundle.Findings, exportFinding{ID: f.ID.String(), Title: f.Title, Severity: string(f.Severity), Status: string(f.Status)})
	}
	for _, e := range evidencePage.Items {
		bundle.Evidence = append(bundle.Evidence, exportEvidence{SourceType: string(e.SourceType), SourceID: e.SourceID.String(), ObservedAt: e.ObservedAt.Format(time.RFC3339)})
	}
	for _, e := range timelinePage.Items {
		bundle.Timeline = append(bundle.Timeline, exportTimelineEvent{Timestamp: e.Timestamp.Format(time.RFC3339), Type: string(e.Type), Title: e.Title})
	}
	for _, r := range relPage.Items {
		bundle.Relationships = append(bundle.Relationships, exportRelationship{Type: string(r.Type), Status: string(r.Status), Score: r.Score, Explanation: r.Explanation})
	}
	for _, h := range hyps {
		bundle.Hypotheses = append(bundle.Hypotheses, exportHypothesis{Title: h.Title, Status: string(h.Status)})
	}
	for _, n := range notes {
		bundle.Notes = append(bundle.Notes, exportNote{AuthorID: n.AuthorID, Content: n.Content, CreatedAt: n.CreatedAt.Format(time.RFC3339)})
	}
	return bundle, nil
}

// Export renders bundle in the requested format.
func Export(bundle ExportBundle, format ExportFormat) ([]byte, error) {
	switch format {
	case ExportCSV:
		return exportCSV(bundle)
	case ExportMarkdown:
		return exportMarkdown(bundle), nil
	default:
		return json.MarshalIndent(bundle, "", "  ")
	}
}

func exportCSV(bundle ExportBundle) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"section", "field1", "field2", "field3"}); err != nil {
		return nil, err
	}
	for _, f := range bundle.Findings {
		if err := w.Write([]string{"finding", f.ID, f.Title, f.Severity + "/" + f.Status}); err != nil {
			return nil, err
		}
	}
	for _, e := range bundle.Timeline {
		if err := w.Write([]string{"timeline", e.Timestamp, string(e.Type), e.Title}); err != nil {
			return nil, err
		}
	}
	for _, r := range bundle.Relationships {
		if err := w.Write([]string{"relationship", string(r.Type), string(r.Status), r.Explanation}); err != nil {
			return nil, err
		}
	}
	for _, h := range bundle.Hypotheses {
		if err := w.Write([]string{"hypothesis", h.Title, string(h.Status), ""}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func exportMarkdown(bundle ExportBundle) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# %s\n\n", bundle.Summary.Title)
	fmt.Fprintf(&buf, "## Executive Summary\n\nStatus: %s  \nSeverity: %s  \nConfidence: %s  \nPriority: %s  \nAssigned to: %s\n\n",
		bundle.Summary.Status, bundle.Summary.Severity, bundle.Summary.Confidence, bundle.Summary.Priority, bundle.Summary.AssignedTo)
	fmt.Fprintf(&buf, "## Scope\n\nAssets: %d  \nEndpoints: %d  \nFindings: %d (%d open)\n\n",
		bundle.Summary.AssetCount, bundle.Summary.EndpointCount, bundle.Summary.FindingCount, bundle.Summary.OpenFindingCount)

	fmt.Fprintf(&buf, "## Findings\n\n")
	for _, f := range bundle.Findings {
		fmt.Fprintf(&buf, "- **%s** — %s (%s)\n", f.Title, f.Severity, f.Status)
	}

	fmt.Fprintf(&buf, "\n## Timeline\n\n")
	for _, e := range bundle.Timeline {
		fmt.Fprintf(&buf, "- %s — %s\n", e.Timestamp, e.Title)
	}

	fmt.Fprintf(&buf, "\n## Correlations\n\n")
	for _, r := range bundle.Relationships {
		fmt.Fprintf(&buf, "- **%s** (%s, score %d): %s\n", r.Type, r.Status, r.Score, r.Explanation)
	}

	fmt.Fprintf(&buf, "\n## Hypotheses\n\n")
	for _, h := range bundle.Hypotheses {
		fmt.Fprintf(&buf, "- **%s** — %s\n", h.Title, h.Status)
	}

	fmt.Fprintf(&buf, "\n## Analyst Notes\n\n")
	for _, n := range bundle.Notes {
		fmt.Fprintf(&buf, "- [%s] %s: %s\n", n.CreatedAt, n.AuthorID, n.Content)
	}

	fmt.Fprintf(&buf, "\n## Current Status\n\n%s\n", bundle.Summary.Status)
	return buf.Bytes()
}
