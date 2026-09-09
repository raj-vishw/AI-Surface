package detectors

import (
	"context"
	"strings"

	"github.com/Masterminds/semver/v3"

	"ai-surface-platform/internal/detection"
)

// VulnerabilityMapping links one technology + version constraint to a
// known vulnerability (phase8.md §41). It is never invented at runtime —
// every field must come from an actual vulnerability catalog/feed.
type VulnerabilityMapping struct {
	Technology        string // matched case-insensitively against fingerprint.Technology
	VersionConstraint string // a github.com/Masterminds/semver/v3 constraint, e.g. ">=1.0.0, <1.18.4"
	ID                string // e.g. a CVE identifier — never guessed (phase8.md §89)
	Severity          detection.Severity
	Reference         detection.Reference
	Description       string
}

// VulnerabilityCatalog holds known technology/version -> vulnerability
// mappings (phase8.md §41's "VulnerabilityCatalog" abstraction). The
// built-in NewEmptyVulnerabilityCatalog ships with zero entries — this
// phase deliberately does not hardcode CVE data (phase8.md §41/§89: "do
// not hardcode thousands of CVEs... do not generate false CVE matches...
// do not guess CVEs"); it exists so a future phase (or an operator) can
// load a real feed into it without changing technologyVulnerabilityDetector
// itself.
type VulnerabilityCatalog struct {
	mappings []VulnerabilityMapping
}

// NewEmptyVulnerabilityCatalog returns a catalog with no entries.
func NewEmptyVulnerabilityCatalog() *VulnerabilityCatalog {
	return &VulnerabilityCatalog{}
}

// NewVulnerabilityCatalog returns a catalog seeded with mappings — used by
// tests and by any future feed-loading integration; never called with
// hardcoded production CVE data by this package itself.
func NewVulnerabilityCatalog(mappings []VulnerabilityMapping) *VulnerabilityCatalog {
	return &VulnerabilityCatalog{mappings: mappings}
}

// Match returns every mapping whose Technology matches (case-insensitive)
// and whose VersionConstraint is satisfied by version. An unparseable
// version or constraint is skipped, never guessed at.
func (c *VulnerabilityCatalog) Match(technology, version string) []VulnerabilityMapping {
	if c == nil || version == "" {
		return nil
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return nil
	}

	var out []VulnerabilityMapping
	for _, m := range c.mappings {
		if !strings.EqualFold(m.Technology, technology) {
			continue
		}
		constraint, err := semver.NewConstraint(m.VersionConstraint)
		if err != nil || !constraint.Check(v) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// technologyVulnerabilityDetector reports a fingerprinted technology whose
// exact observed version matches a VulnerabilityCatalog entry (phase8.md
// §40/§41). With the default empty catalog it produces no findings ever —
// the detector exists and is fully tested, but making an actual CVE claim
// requires a real, externally-sourced catalog to be loaded first.
type technologyVulnerabilityDetector struct {
	catalog *VulnerabilityCatalog
}

// NewTechnologyVulnerabilityDetector builds the detector backed by
// catalog. Passing nil is equivalent to NewEmptyVulnerabilityCatalog().
func NewTechnologyVulnerabilityDetector(catalog *VulnerabilityCatalog) detection.Detector {
	if catalog == nil {
		catalog = NewEmptyVulnerabilityCatalog()
	}
	return technologyVulnerabilityDetector{catalog: catalog}
}

func (technologyVulnerabilityDetector) ID() string   { return "technology.known-vulnerability" }
func (technologyVulnerabilityDetector) Name() string { return "Known Technology Vulnerability" }
func (technologyVulnerabilityDetector) Description() string {
	return "Reports a fingerprinted technology/version matching a loaded vulnerability catalog entry."
}
func (technologyVulnerabilityDetector) Version() int { return 1 }
func (technologyVulnerabilityDetector) Category() detection.Category {
	return detection.CategoryTechnology
}
func (technologyVulnerabilityDetector) Mode() detection.DetectorMode {
	return detection.DetectorPassive
}

func (d technologyVulnerabilityDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, fp := range input.Fingerprints {
		if fp.Version == "" {
			continue
		}
		for _, m := range d.catalog.Match(fp.Technology, fp.Version) {
			findings = append(findings, detection.Finding{
				AssetID: input.Asset.ID, DetectorID: d.ID(), DetectorVersion: d.Version(),
				Title:       "Known vulnerability in " + fp.Technology + " " + fp.Version + " (" + m.ID + ")",
				Description: m.Description,
				Category:    detection.CategoryTechnology, Scope: detection.ScopeAsset,
				Severity: m.Severity, Confidence: detection.Confidence(fp.Confidence),
				Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceTechnology, map[string]any{
					"technology": fp.Technology, "version": fp.Version, "vulnerability_id": m.ID,
				}, detection.Confidence(fp.Confidence))},
				Remediation: "Upgrade " + fp.Technology + " past the affected version range.",
				References:  []detection.Reference{m.Reference, detection.ReferenceOWASPVulnerableComponents},
			})
		}
	}
	return findings, nil
}
