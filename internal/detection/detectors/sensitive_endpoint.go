package detectors

import (
	"context"
	"regexp"

	"ai-recon-platform/internal/detection"
)

// sensitivePathPattern matches path shapes worth flagging purely from
// their observed location — admin panels, debug/actuator endpoints, and
// common CMS management paths — never fetched or probed beyond what
// discovery already requested (phase8.md §29's "only use evidence already
// obtained by existing discovery").
var sensitivePathPattern = regexp.MustCompile(`(?i)/(admin|administrator|manage|management|debug|actuator|console|phpmyadmin|wp-admin|_profiler|adminer)(/|$)`)

// sensitiveEndpointDetector reports an already-observed, publicly
// reachable endpoint whose path shape suggests an administrative or
// debug surface (phase8.md structure's "sensitive_endpoint.go"). It is
// inventory-only: informational severity, no attempt to access anything
// beyond the response discovery already retrieved.
type sensitiveEndpointDetector struct{}

func (sensitiveEndpointDetector) ID() string   { return "exposure.sensitive-endpoint-shape" }
func (sensitiveEndpointDetector) Name() string { return "Sensitive-Shaped Endpoint Discovered" }
func (sensitiveEndpointDetector) Description() string {
	return "Reports a publicly reachable endpoint whose path suggests an admin/debug surface."
}
func (sensitiveEndpointDetector) Version() int                 { return 1 }
func (sensitiveEndpointDetector) Category() detection.Category { return detection.CategoryExposure }
func (sensitiveEndpointDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d sensitiveEndpointDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !ep.Observed || ep.StatusCode == 0 || ep.StatusCode >= 400 {
			continue
		}
		if !sensitivePathPattern.MatchString(ep.Path) {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Sensitive-shaped endpoint reachable",
			Description: "A publicly reachable endpoint was observed at a path commonly used for administrative, debugging, or management interfaces. This reports the path shape only — its contents were not further inspected.",
			Category:    detection.CategoryExposure, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityInformational, Confidence: 0.5,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceEndpointMeta, map[string]any{
				"url": endpointLabel(ep), "path": ep.Path, "status_code": ep.StatusCode,
			}, 0.5)},
			Remediation: "Confirm this interface requires authentication and is not intended to be restricted to an internal network only.",
		})
	}
	return findings, nil
}
