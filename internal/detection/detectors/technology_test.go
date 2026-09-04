package detectors

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

func TestVulnerabilityCatalog_MatchesInRange(t *testing.T) {
	catalog := NewVulnerabilityCatalog([]VulnerabilityMapping{
		{Technology: "nginx", VersionConstraint: "< 1.18.4", ID: "TEST-0001", Severity: detection.SeverityHigh},
	})
	matches := catalog.Match("nginx", "1.18.0")
	if len(matches) != 1 || matches[0].ID != "TEST-0001" {
		t.Fatalf("expected 1 match, got %#v", matches)
	}
}

func TestVulnerabilityCatalog_NoMatchOutsideRange(t *testing.T) {
	catalog := NewVulnerabilityCatalog([]VulnerabilityMapping{
		{Technology: "nginx", VersionConstraint: "< 1.18.4", ID: "TEST-0001"},
	})
	if matches := catalog.Match("nginx", "1.20.0"); len(matches) != 0 {
		t.Fatalf("expected no match outside the constraint range, got %#v", matches)
	}
}

func TestVulnerabilityCatalog_CaseInsensitiveTechnology(t *testing.T) {
	catalog := NewVulnerabilityCatalog([]VulnerabilityMapping{
		{Technology: "nginx", VersionConstraint: "< 2.0.0", ID: "TEST-0001"},
	})
	if matches := catalog.Match("Nginx", "1.0.0"); len(matches) != 1 {
		t.Fatalf("expected case-insensitive technology match, got %#v", matches)
	}
}

func TestVulnerabilityCatalog_UnparseableVersionSkipped(t *testing.T) {
	catalog := NewVulnerabilityCatalog([]VulnerabilityMapping{
		{Technology: "nginx", VersionConstraint: "< 2.0.0", ID: "TEST-0001"},
	})
	if matches := catalog.Match("nginx", "not-a-version"); len(matches) != 0 {
		t.Fatalf("expected no match for an unparseable version, got %#v", matches)
	}
}

func TestEmptyVulnerabilityCatalog_NeverMatches(t *testing.T) {
	catalog := NewEmptyVulnerabilityCatalog()
	if matches := catalog.Match("nginx", "1.0.0"); len(matches) != 0 {
		t.Fatalf("expected the default empty catalog to never match, got %#v", matches)
	}
}

func TestTechnologyVulnerabilityDetector_DefaultCatalogProducesNoFindings(t *testing.T) {
	d := NewTechnologyVulnerabilityDetector(nil)
	input := detection.Input{
		Asset:        detection.AssetObservation{ID: uuid.New()},
		Fingerprints: []detection.FingerprintObservation{{Technology: "nginx", Version: "1.18.0", Confidence: 0.9}},
	}
	findings, err := d.Detect(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected zero findings from the default empty catalog, got %#v", findings)
	}
}

func TestTechnologyVulnerabilityDetector_ReportsCatalogMatch(t *testing.T) {
	catalog := NewVulnerabilityCatalog([]VulnerabilityMapping{
		{Technology: "nginx", VersionConstraint: "< 1.18.4", ID: "TEST-0001", Severity: detection.SeverityHigh, Description: "test mapping"},
	})
	d := NewTechnologyVulnerabilityDetector(catalog)
	input := detection.Input{
		Asset:        detection.AssetObservation{ID: uuid.New()},
		Fingerprints: []detection.FingerprintObservation{{Technology: "nginx", Version: "1.18.0", Confidence: 0.9}},
	}
	findings, _ := d.Detect(context.Background(), input)
	if len(findings) != 1 || findings[0].Severity != detection.SeverityHigh {
		t.Fatalf("expected 1 high-severity finding, got %#v", findings)
	}
}
