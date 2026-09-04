package detectors

import (
	"context"
	"regexp"

	"ai-recon-platform/internal/detection"
)

// versionPattern requires a digit somewhere after the product name — a
// bare "Server: nginx" is a product marker, not itself disclosure; only a
// version *number* is treated as information disclosure (phase8.md §26:
// "a version string alone is not necessarily a vulnerability" — this
// detector still reports it, deliberately at low severity/informational,
// as inventory-relevant disclosure, not a vulnerability claim).
var versionPattern = regexp.MustCompile(`\d+\.\d+`)

// informationDisclosureDetector flags response headers that expose a
// concrete software version (Server, X-Powered-By, and the other
// framework-marker headers this project already captures — phase8.md
// §26). Conservative by construction: it only fires when a version-number
// pattern is present, never merely because a header exists.
type informationDisclosureDetector struct{}

func (informationDisclosureDetector) ID() string   { return "information_disclosure.version-exposure" }
func (informationDisclosureDetector) Name() string { return "Software Version Disclosure" }
func (informationDisclosureDetector) Description() string {
	return "Detects response headers that expose a specific software version number."
}
func (informationDisclosureDetector) Version() int { return 1 }
func (informationDisclosureDetector) Category() detection.Category {
	return detection.CategoryInformationDisclosure
}
func (informationDisclosureDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

// disclosureHeaders are the already-captured headers worth checking for a
// version number — a closed list matching exactly what
// internal/discovery/service/discovery.go's fingerprintHeaderAllowlist
// captures (this detector invents no new header capture of its own).
var disclosureHeaders = []string{
	"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
	"X-Generator", "X-Runtime", "X-Application-Context",
}

func (d informationDisclosureDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !httpAnalyzed(ep) {
			continue
		}
		for _, name := range disclosureHeaders {
			var value string
			if name == "Server" {
				value = stringFromMetadata(ep.Metadata, "server")
			} else {
				value = headerFromMetadata(ep.Metadata, name)
			}
			if value == "" || !versionPattern.MatchString(value) {
				continue
			}
			id := ep.ID
			findings = append(findings, detection.Finding{
				EndpointID: &id, DetectorID: d.ID() + "." + name, DetectorVersion: d.Version(),
				Title:       "Version disclosed via " + name,
				Description: "The " + name + " response header discloses a specific software version, which narrows the set of known vulnerabilities an attacker needs to check for this component.",
				Category:    detection.CategoryInformationDisclosure, Scope: detection.ScopeEndpoint,
				Severity: detection.SeverityInformational, Confidence: 0.8,
				Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceHTTPHeader, map[string]any{
					"url": endpointLabel(ep), "header": name, "value": value,
				}, 0.8)},
				Remediation: "Suppress or generalize version-identifying response headers in production.",
				References:  []detection.Reference{detection.ReferenceOWASPSecurityMisconfiguration},
			})
		}
	}
	return findings, nil
}
