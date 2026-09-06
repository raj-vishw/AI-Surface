package reporting

import (
	"bytes"
	"encoding/csv"
	"fmt"
)

// dangerousCSVPrefixes are the leading characters spreadsheet
// applications (Excel, Google Sheets, LibreOffice) interpret as the
// start of a formula — phase14.md §95's "CSV injection" / §106's worked
// examples (=SUM(...), +123, -123, @example). A cell beginning with any
// of these is neutralized by prefixing a single quote, the standard
// OWASP-recommended mitigation, which every common spreadsheet
// application renders as the literal text rather than evaluating it.
var dangerousCSVPrefixes = []byte{'=', '+', '-', '@', '\t', '\r'}

// EscapeCSVValue neutralizes formula-injection-shaped values (phase14.md
// §95/§106). It never alters a value that doesn't start with a
// dangerous prefix — an ordinary negative number written in a
// non-leading position, or free text, passes through unchanged.
func EscapeCSVValue(s string) string {
	if s == "" {
		return s
	}
	for _, p := range dangerousCSVPrefixes {
		if s[0] == p {
			return "'" + s
		}
	}
	return s
}

// EncodeCSV renders headers+rows as CSV (phase14.md §43): stable
// columns, comma/newline/Unicode handled correctly by the standard
// library's encoding/csv writer (which quotes any field containing a
// comma, quote, or newline per RFC 4180), and every value passed through
// EscapeCSVValue first (phase14.md §95). Never includes a column caller
// data hasn't explicitly supplied — secret redaction is the caller's
// responsibility before values ever reach this function (see
// internal/service/reporting, which redacts via internal/ai.Redact
// first).
func EncodeCSV(headers []string, rows [][]string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	escapedHeaders := make([]string, len(headers))
	for i, h := range headers {
		escapedHeaders[i] = EscapeCSVValue(h)
	}
	if err := w.Write(escapedHeaders); err != nil {
		return nil, fmt.Errorf("writing CSV header: %w", err)
	}

	for i, row := range rows {
		if len(row) != len(headers) {
			return nil, fmt.Errorf("CSV row %d has %d values, want %d (stable columns required)", i, len(row), len(headers))
		}
		escaped := make([]string, len(row))
		for j, v := range row {
			escaped[j] = EscapeCSVValue(v)
		}
		if err := w.Write(escaped); err != nil {
			return nil, fmt.Errorf("writing CSV row %d: %w", i, err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flushing CSV: %w", err)
	}
	return buf.Bytes(), nil
}
