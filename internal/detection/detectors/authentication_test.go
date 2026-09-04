package detectors

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

func TestAuthSurfaceDetector_HTTPSInventoryOnly(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/login", Classification: "auth", Observed: true}
	findings, err := authSurfaceDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != detection.SeverityInformational {
		t.Fatalf("expected 1 informational finding over HTTPS, got %#v", findings)
	}
}

func TestAuthSurfaceDetector_PlainHTTPElevatedSeverity(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "http://example.test/login", Classification: "auth", Observed: true}
	findings, _ := authSurfaceDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 1 || findings[0].Severity != detection.SeverityMedium {
		t.Fatalf("expected 1 medium finding over plain HTTP, got %#v", findings)
	}
}

func TestAuthSurfaceDetector_IgnoresNonAuthEndpoints(t *testing.T) {
	ep := detection.EndpointObservation{ID: uuid.New(), URL: "https://example.test/about", Classification: "page", Observed: true}
	findings, _ := authSurfaceDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a non-auth endpoint, got %d", len(findings))
	}
}
