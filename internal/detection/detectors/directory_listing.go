package detectors

import (
	"context"
	"regexp"

	"ai-recon-platform/internal/detection"
)

// directoryListingMarkers are patterns produced by common web-server
// autoindex features (Apache/nginx) — deliberately specific title/anchor
// text, not a bare word like "index" (phase8.md §28: "only report when
// confidently identified").
var directoryListingMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<title>\s*Index of /`),
	regexp.MustCompile(`(?i)Index of /[\w./-]*\s*</h1>`),
	regexp.MustCompile(`(?i)Parent Directory</a>`),
	regexp.MustCompile(`(?i)\[To Parent Directory\]`),
}

// directoryListingDetector re-requests (bounded, safe-active only) an
// already-known, already-observed HTML-ish endpoint and checks the fresh
// body for a directory-index marker (phase8.md §28). It never brute-forces
// candidate directory paths — only endpoints discovery already found are
// ever re-checked.
type directoryListingDetector struct{}

func (directoryListingDetector) ID() string   { return "directory_listing.autoindex" }
func (directoryListingDetector) Name() string { return "Directory Listing Enabled" }
func (directoryListingDetector) Description() string {
	return "Re-checks an already-observed endpoint for a web-server directory-index marker."
}
func (directoryListingDetector) Version() int                 { return 1 }
func (directoryListingDetector) Category() detection.Category { return detection.CategoryExposure }
func (directoryListingDetector) Mode() detection.DetectorMode { return detection.DetectorSafeActive }

func (d directoryListingDetector) Detect(ctx context.Context, input detection.Input) ([]detection.Finding, error) {
	if !safeActiveReady(input) {
		return nil, nil
	}
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !ep.Observed || ep.StatusCode < 200 || ep.StatusCode >= 300 || ep.URL == "" {
			continue
		}
		if !looksLikeHTMLResponse(ep.ContentType, ep.Classification) {
			continue
		}
		result, err := input.Fetcher.Fetch(ctx, ep.URL, maxResponseBytes(input.Config))
		if err != nil {
			continue
		}
		body := string(result.Body)
		loc := findFirstMatch(directoryListingMarkers, body)
		if loc == nil {
			continue
		}

		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Directory listing enabled",
			Description: "A re-check of this endpoint found a web-server directory-index marker (e.g. \"Index of /\"), indicating directory browsing is enabled and the directory's contents are enumerable.",
			Category:    detection.CategoryExposure, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityMedium, Confidence: 0.85,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceResponseExcerpt, map[string]any{
				"url": endpointLabel(ep), "status_code": result.StatusCode,
				"excerpt": detection.TruncateExcerpt(excerptAround(body, loc[0], loc[1], 60), input.Config.ExcerptLimit()),
			}, 0.85)},
			Remediation: "Disable directory autoindexing at the web server for this path.",
		})
	}
	return findings, nil
}
