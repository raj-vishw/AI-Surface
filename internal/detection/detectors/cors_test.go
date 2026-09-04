package detectors

import (
	"context"
	"testing"

	"ai-recon-platform/internal/detection"
)

func TestCORSDetector_WildcardWithCredentials(t *testing.T) {
	ep := httpEndpoint("https://example.test/api", 200, map[string]any{
		"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
	})
	findings, err := corsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestCORSDetector_ScopedOriginNoFinding(t *testing.T) {
	ep := httpEndpoint("https://example.test/api", 200, map[string]any{
		"Access-Control-Allow-Origin": "https://trusted.example",
	})
	findings, _ := corsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a scoped origin, got %#v", findings)
	}
}

func TestCORSDetector_WildcardWithoutCredentialsNoFinding(t *testing.T) {
	ep := httpEndpoint("https://example.test/api", 200, map[string]any{
		"Access-Control-Allow-Origin": "*",
	})
	findings, _ := corsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for wildcard without credentials, got %#v", findings)
	}
}
