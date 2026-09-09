package detectors

import (
	"context"
	"strconv"

	"ai-surface-platform/internal/detection"
)

// sensitiveOpenPorts are TCP ports Phase 4 already treats as
// administrative/database candidate ports (see internal/discovery/network's
// AI/HTTP-candidate configuration for the analogous pattern) that are
// especially unexpected to find open on a public-facing host. Reported
// informational/low — an open database port is not itself proof of
// exposure (it may still require valid credentials), only worth a
// reviewer's attention (phase8.md's exposed_services.go: "exposed
// services" from already-collected Phase 4 evidence, never a fresh scan).
var sensitiveOpenPorts = map[int]string{
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
	2379:  "etcd",
	11211: "Memcached",
	5984:  "CouchDB",
	1433:  "Microsoft SQL Server",
}

// exposedServiceDetector reports a Phase 4-observed OPEN port matching a
// known administrative/database service on the asset's own host
// (phase8.md's exposed_services.go). It performs no connection of its
// own — the port's OPEN state and Service classification come entirely
// from Phase 4's already-persisted TCP-connect result.
type exposedServiceDetector struct{}

func (exposedServiceDetector) ID() string   { return "exposure.sensitive-open-port" }
func (exposedServiceDetector) Name() string { return "Sensitive Service Port Open" }
func (exposedServiceDetector) Description() string {
	return "Reports an open database/administrative service port already observed by network discovery."
}
func (exposedServiceDetector) Version() int                 { return 1 }
func (exposedServiceDetector) Category() detection.Category { return detection.CategoryExposure }
func (exposedServiceDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d exposedServiceDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, svc := range input.Services {
		if svc.State != "OPEN" {
			continue
		}
		label, sensitive := sensitiveOpenPorts[svc.Port]
		if !sensitive {
			continue
		}
		findings = append(findings, detection.Finding{
			AssetID: input.Asset.ID, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       label + " port (" + strconv.Itoa(svc.Port) + ") reachable",
			Description: "Port " + strconv.Itoa(svc.Port) + " (commonly " + label + ") was observed OPEN on " + svc.Host + ". This reports reachability only — no connection attempt beyond the TCP handshake was made, and no credentials were tested.",
			Category:    detection.CategoryExposure, Scope: detection.ScopeAsset,
			Severity: detection.SeverityLow, Confidence: 0.7,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceServiceMeta, map[string]any{
				"host": svc.Host, "port": svc.Port, "service": svc.Service, "state": svc.State, "assumed_service": label,
			}, 0.7)},
			Remediation: "Restrict this port to trusted networks (VPN/private subnet/firewall allow-list) unless it is intentionally public, and confirm authentication is enforced.",
		})
	}
	return findings, nil
}
