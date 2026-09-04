package detectors

import (
	"context"
	"strings"

	"ai-recon-platform/internal/detection"
)

// corsDetector flags the specific dangerous combination phase8.md §34
// calls out — Access-Control-Allow-Origin: * together with
// Access-Control-Allow-Credentials: true — established directly from
// already-observed response headers. It never sends a probing Origin
// header of its own; that would require a fresh request this passive
// detector never makes (phase8.md §34: "do not send arbitrary Origin
// headers unless a safe-active CORS check is explicitly enabled" — no
// such safe-active variant is implemented in this phase).
type corsDetector struct{}

func (corsDetector) ID() string   { return "cors.wildcard-with-credentials" }
func (corsDetector) Name() string { return "Dangerous CORS Configuration" }
func (corsDetector) Description() string {
	return "Detects Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true."
}
func (corsDetector) Version() int                 { return 1 }
func (corsDetector) Category() detection.Category { return detection.CategoryWeb }
func (corsDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d corsDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !httpAnalyzed(ep) {
			continue
		}
		acao := strings.TrimSpace(headerFromMetadata(ep.Metadata, "Access-Control-Allow-Origin"))
		acac := strings.EqualFold(strings.TrimSpace(headerFromMetadata(ep.Metadata, "Access-Control-Allow-Credentials")), "true")
		if acao != "*" || !acac {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Dangerous CORS configuration",
			Description: "This response sent Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true — a configuration browsers are supposed to reject, but which some clients/proxies still honor, and which signals the CORS policy was not deliberately scoped to trusted origins.",
			Category:    detection.CategoryWeb, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityMedium, Confidence: 0.85,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
				"url": endpointLabel(ep), "access_control_allow_origin": acao, "access_control_allow_credentials": true,
			}, 0.85)},
			Remediation: "Never combine a wildcard Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true; reflect a specific, validated allow-list of origins instead.",
			References:  []detection.Reference{detection.ReferenceMDNCORS, detection.ReferenceOWASPSecurityMisconfiguration},
		})
	}
	return findings, nil
}
