package detectors

import (
	"context"
	"regexp"

	"ai-surface-platform/internal/detection"
)

// errorMarkerPatterns are strong, low-false-positive indicators of a
// framework/database error page or stack trace (phase8.md §26/§27/§62:
// "strong evidence -> finding; weak keyword only -> no finding" — none of
// these match on a bare word like "database" or "error" alone).
var errorMarkerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)\bat [\w.$]+\([\w.]+\.java:\d+\)`),
	regexp.MustCompile(`\b[\w.]+Exception\b.{0,120}\bat\b`),
	regexp.MustCompile(`(?i)System\.\w+Exception`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for`),
	regexp.MustCompile(`(?i)ORA-\d{5}`),
	regexp.MustCompile(`(?i)PostgreSQL.{0,40}ERROR:`),
	regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
	regexp.MustCompile(`(?i)Warning: (mysqli?|pg)_[a-z_]+\(\)`),
	regexp.MustCompile(`(?i)Fatal error: Uncaught`),
	regexp.MustCompile(`(?i)panic:.{0,80}\[recovered\]`),
	regexp.MustCompile(`(?i)django\.core\.exceptions`),
}

// errorDisclosureDetector re-requests (bounded, safe-active only) an
// already-known endpoint that was previously observed returning a server
// error, and checks the fresh body against errorMarkerPatterns
// (phase8.md §27). It never guesses a new path to provoke an error —
// only endpoints discovery already found returning 5xx are ever
// re-checked, and only a short, sanitized excerpt around the match is
// ever recorded, never the full response.
type errorDisclosureDetector struct{}

func (errorDisclosureDetector) ID() string   { return "error_disclosure.stack-trace" }
func (errorDisclosureDetector) Name() string { return "Error/Stack Trace Disclosure" }
func (errorDisclosureDetector) Description() string {
	return "Re-checks an already-observed error response for a strong stack-trace/framework-error marker."
}
func (errorDisclosureDetector) Version() int { return 1 }
func (errorDisclosureDetector) Category() detection.Category {
	return detection.CategoryInformationDisclosure
}
func (errorDisclosureDetector) Mode() detection.DetectorMode { return detection.DetectorSafeActive }

func (d errorDisclosureDetector) Detect(ctx context.Context, input detection.Input) ([]detection.Finding, error) {
	if !safeActiveReady(input) {
		return nil, nil
	}
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !ep.Observed || ep.StatusCode < 500 || ep.URL == "" {
			continue
		}
		result, err := input.Fetcher.Fetch(ctx, ep.URL, maxResponseBytes(input.Config))
		if err != nil {
			continue
		}
		body := string(result.Body)
		loc := findFirstMatch(errorMarkerPatterns, body)
		if loc == nil {
			continue
		}

		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Error response discloses stack trace or internal detail",
			Description: "A re-check of this already-observed error response found a strong framework/database error or stack-trace marker, which can disclose internal file paths, class names, or query structure to an unauthenticated visitor.",
			Category:    detection.CategoryInformationDisclosure, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityLow, Confidence: 0.75,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceResponseExcerpt, map[string]any{
				"url": endpointLabel(ep), "status_code": result.StatusCode,
				"excerpt": detection.TruncateExcerpt(excerptAround(body, loc[0], loc[1], 100), input.Config.ExcerptLimit()),
			}, 0.75)},
			Remediation: "Disable verbose/debug error output in production and return a generic error page instead.",
		})
	}
	return findings, nil
}

// findFirstMatch returns the [start, end) byte range of the first pattern
// in patterns that matches body, or nil if none do.
func findFirstMatch(patterns []*regexp.Regexp, body string) []int {
	for _, p := range patterns {
		if loc := p.FindStringIndex(body); loc != nil {
			return loc
		}
	}
	return nil
}

// excerptAround returns a bounded window of s centered on [start, end) —
// used so evidence carries just enough surrounding context to be useful
// without pulling in the entire response body.
func excerptAround(s string, start, end, context int) string {
	from := start - context
	if from < 0 {
		from = 0
	}
	to := end + context
	if to > len(s) {
		to = len(s)
	}
	return s[from:to]
}
