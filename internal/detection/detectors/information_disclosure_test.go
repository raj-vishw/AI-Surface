package detectors

import (
	"context"
	"testing"

	"ai-recon-platform/internal/detection"
)

func TestInformationDisclosureDetector_VersionExposed(t *testing.T) {
	ep := httpEndpoint("https://example.test/", 200, nil)
	ep.Metadata["server"] = "nginx/1.18.0"
	findings, err := informationDisclosureDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a version-bearing Server header, got %d", len(findings))
	}
}

func TestInformationDisclosureDetector_BareProductNameNotFlagged(t *testing.T) {
	// phase8.md §26: "a version string alone is not necessarily a
	// vulnerability" — a bare product name with no version number must
	// not be flagged at all.
	ep := httpEndpoint("https://example.test/", 200, nil)
	ep.Metadata["server"] = "nginx"
	findings, _ := informationDisclosureDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a bare product name, got %#v", findings)
	}
}

func TestInformationDisclosureDetector_XPoweredByVersion(t *testing.T) {
	ep := httpEndpoint("https://example.test/", 200, map[string]any{"X-Powered-By": "PHP/8.2.1"})
	findings, _ := informationDisclosureDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for X-Powered-By with a version, got %d", len(findings))
	}
}
