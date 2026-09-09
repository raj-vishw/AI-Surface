package reporting

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	rept "ai-surface-platform/internal/reporting"
)

// Export implements phase14.md §42/§43/§44: renders a persisted report
// as JSON or CSV. Content is redacted a second time here (defense in
// depth — see internal/reporting.RedactSections's own doc comment)
// before being rendered, even though generation already redacted it
// once.
func (s *Service) Export(ctx context.Context, reportID uuid.UUID, format string) ([]byte, error) {
	report, err := s.reports.GetReportByID(ctx, reportID)
	if err != nil {
		return nil, err
	}

	var envelope rept.Envelope
	if err := json.Unmarshal([]byte(report.Content), &envelope); err != nil {
		return nil, fmt.Errorf("decoding stored report content: %w", err)
	}
	envelope.Data = rept.RedactSections(envelope.Data)
	envelope.Metadata.Status = string(report.Status)
	envelope.Metadata.ContentHash = report.ContentHash
	envelope.Metadata.Provider = report.Provider
	envelope.Metadata.Model = report.Model
	envelope.Metadata.PromptVersion = report.PromptVersion
	envelope.GeneratedAt = report.GeneratedAt

	switch format {
	case "", "json":
		return rept.EncodeJSON(envelope)
	case "csv":
		headers := []string{"section", "body", "citations"}
		rows := make([][]string, 0, len(envelope.Data))
		for _, sec := range envelope.Data {
			citations := ""
			for i, c := range sec.Citations {
				if i > 0 {
					citations += "; "
				}
				citations += c
			}
			rows = append(rows, []string{sec.Title, sec.Body, citations})
		}
		return rept.EncodeCSV(headers, rows)
	default:
		return nil, fmt.Errorf("unsupported export format %q — must be \"json\" or \"csv\"", format)
	}
}
