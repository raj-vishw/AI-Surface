package detectors

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"ai-recon-platform/internal/detection"
)

func httpEndpoint(url string, statusCode int, headers map[string]any) detection.EndpointObservation {
	metadata := map[string]any{"discovery_method": "http", "status_code": statusCode}
	if len(headers) > 0 {
		metadata["headers"] = headers
	}
	return detection.EndpointObservation{
		ID: uuid.New(), URL: url, Method: "GET", StatusCode: statusCode,
		ContentType: "text/html", Classification: "page", Observed: true, Metadata: metadata,
	}
}

func TestHSTSDetector_MissingOnHTTPS(t *testing.T) {
	ep := httpEndpoint("https://example.test/", 200, nil)
	findings, err := hstsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestHSTSDetector_PresentOnHTTPS(t *testing.T) {
	ep := httpEndpoint("https://example.test/", 200, map[string]any{"Strict-Transport-Security": "max-age=63072000"})
	findings, _ := hstsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding when HSTS present, got %d", len(findings))
	}
}

func TestHSTSDetector_NeverFiresOnPlainHTTP(t *testing.T) {
	ep := httpEndpoint("http://example.test/", 200, nil)
	findings, _ := hstsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no HSTS finding for plain HTTP, got %d", len(findings))
	}
}

func TestHSTSDetector_SkipsEndpointsWithoutHeaderEvidence(t *testing.T) {
	// A Phase 7-only crawl result: no discovery_method=="http", so no
	// header evidence was ever captured — must not be reported as missing.
	ep := detection.EndpointObservation{
		ID: uuid.New(), URL: "https://example.test/", StatusCode: 200, Observed: true,
		Metadata: map[string]any{"discovery_method": "endpoint"},
	}
	findings, _ := hstsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding without header evidence, got %d", len(findings))
	}
}

func TestCSPDetector_MissingAndWeak(t *testing.T) {
	missing := httpEndpoint("https://example.test/", 200, nil)
	findings, _ := cspDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{missing}})
	if len(findings) != 1 || findings[0].Severity != detection.SeverityMedium {
		t.Fatalf("expected 1 medium finding for missing CSP, got %#v", findings)
	}

	weak := httpEndpoint("https://example.test/", 200, map[string]any{
		"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
	})
	findings, _ = cspDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{weak}})
	if len(findings) != 1 || findings[0].Title != "Weak Content-Security-Policy" {
		t.Fatalf("expected weak CSP finding, got %#v", findings)
	}
}

func TestCSPDetector_WildcardAloneNotAutomaticallyWeak(t *testing.T) {
	// phase8.md §18: a bare "*" (e.g. on img-src) must not be treated as
	// automatically critical/weak.
	ep := httpEndpoint("https://example.test/", 200, map[string]any{
		"Content-Security-Policy": "default-src 'self'; img-src *",
	})
	findings, _ := cspDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a wildcard img-src, got %#v", findings)
	}
}

func TestCSPDetector_ValidPolicyNoFinding(t *testing.T) {
	ep := httpEndpoint("https://example.test/", 200, map[string]any{
		"Content-Security-Policy": "default-src 'self'",
	})
	findings, _ := cspDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a solid CSP, got %#v", findings)
	}
}

func TestXContentTypeOptionsDetector(t *testing.T) {
	missing := httpEndpoint("https://example.test/", 200, nil)
	findings, _ := xContentTypeOptionsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{missing}})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	present := httpEndpoint("https://example.test/", 200, map[string]any{"X-Content-Type-Options": "nosniff"})
	findings, _ = xContentTypeOptionsDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{present}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding when present, got %d", len(findings))
	}
}

func TestReferrerPolicyDetector(t *testing.T) {
	missing := httpEndpoint("https://example.test/", 200, nil)
	findings, _ := referrerPolicyDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{missing}})
	if len(findings) != 1 || findings[0].Title != "Missing Referrer-Policy" {
		t.Fatalf("expected missing finding, got %#v", findings)
	}

	weak := httpEndpoint("https://example.test/", 200, map[string]any{"Referrer-Policy": "unsafe-url"})
	findings, _ = referrerPolicyDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{weak}})
	if len(findings) != 1 || findings[0].Title != "Permissive Referrer-Policy" {
		t.Fatalf("expected permissive finding, got %#v", findings)
	}

	strong := httpEndpoint("https://example.test/", 200, map[string]any{"Referrer-Policy": "strict-origin-when-cross-origin"})
	findings, _ = referrerPolicyDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{strong}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding for a strong policy, got %#v", findings)
	}
}

func TestPermissionsPolicyDetector(t *testing.T) {
	missing := httpEndpoint("https://example.test/", 200, nil)
	findings, _ := permissionsPolicyDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{missing}})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	present := httpEndpoint("https://example.test/", 200, map[string]any{"Permissions-Policy": "geolocation=()"})
	findings, _ = permissionsPolicyDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{present}})
	if len(findings) != 0 {
		t.Fatalf("expected no finding when present, got %d", len(findings))
	}
}

func TestSecurityHeaders_SkipStaticAndAPIResponses(t *testing.T) {
	ep := httpEndpoint("https://example.test/app.js", 200, nil)
	ep.Classification = "static"
	ep.ContentType = "application/javascript"

	findings, _ := cspDetector{}.Detect(context.Background(), detection.Input{Endpoints: []detection.EndpointObservation{ep}})
	if len(findings) != 0 {
		t.Fatalf("expected no CSP finding for a static resource, got %d", len(findings))
	}
}
