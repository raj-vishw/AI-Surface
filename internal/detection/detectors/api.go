package detectors

import (
	"context"

	"ai-recon-platform/internal/detection"
)

// exposedAPIDocDetector reports a publicly reachable OpenAPI/Swagger
// document as an informational/low inventory finding (phase8.md §38) —
// never a critical vulnerability by itself; public API documentation is
// often intentional.
type exposedAPIDocDetector struct{}

func (exposedAPIDocDetector) ID() string   { return "api.exposed-documentation" }
func (exposedAPIDocDetector) Name() string { return "Exposed API Documentation" }
func (exposedAPIDocDetector) Description() string {
	return "Reports publicly reachable OpenAPI/Swagger documentation as an inventory finding."
}
func (exposedAPIDocDetector) Version() int                 { return 1 }
func (exposedAPIDocDetector) Category() detection.Category { return detection.CategoryAPI }
func (exposedAPIDocDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d exposedAPIDocDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !ep.Observed {
			continue
		}
		if ep.Classification != "openapi" && ep.Classification != "swagger" {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Publicly exposed API documentation",
			Description: "A " + ep.Classification + " document was observed to be publicly accessible at this endpoint, disclosing the API's paths, methods, and parameter names.",
			Category:    detection.CategoryAPI, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityLow, Confidence: 0.9,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceOpenAPIMeta, map[string]any{
				"url": endpointLabel(ep), "document_type": ep.Classification, "api_version": ep.APIVersion,
			}, 0.9)},
			Remediation: "Confirm publishing this documentation publicly is intentional; if not, restrict access to it.",
		})
	}
	return findings, nil
}

// graphQLInventoryDetector reports a discovered GraphQL endpoint as an
// informational inventory finding (phase8.md §39). It never introspects,
// enumerates the schema, or executes a query/mutation of its own — the
// finding is purely "a GraphQL endpoint exists here", from Phase 7's own
// path-pattern classification.
type graphQLInventoryDetector struct{}

func (graphQLInventoryDetector) ID() string   { return "api.graphql-endpoint" }
func (graphQLInventoryDetector) Name() string { return "GraphQL Endpoint Discovered" }
func (graphQLInventoryDetector) Description() string {
	return "Reports a discovered GraphQL endpoint as an inventory finding."
}
func (graphQLInventoryDetector) Version() int                 { return 1 }
func (graphQLInventoryDetector) Category() detection.Category { return detection.CategoryAPI }
func (graphQLInventoryDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d graphQLInventoryDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if ep.Classification != "graphql" || !ep.Observed {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Public GraphQL endpoint discovered",
			Description: "A GraphQL endpoint was observed at this path. This is an inventory observation only — its schema was never introspected and no query was ever executed against it.",
			Category:    detection.CategoryAPI, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityInformational, Confidence: 0.7,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceClassification, map[string]any{
				"url": endpointLabel(ep), "classification": "graphql",
			}, 0.7)},
			Remediation: "Confirm introspection is disabled in production and that appropriate query depth/complexity limits and authorization are enforced.",
		})
	}
	return findings, nil
}

// httpMethodExposureDetector reports, purely as inventory, HTTP methods
// an OpenAPI/Swagger document *documents* for an endpoint but that this
// platform never actually observed via a real request (phase8.md §36).
// It never sends DELETE/PUT/PATCH to test them — the distinction between
// "documented" and "confirmed" is exactly Phase 7's Documented/Observed
// split, reused here unchanged.
type httpMethodExposureDetector struct{}

func (httpMethodExposureDetector) ID() string   { return "api.documented-unobserved-method" }
func (httpMethodExposureDetector) Name() string { return "Documented but Unobserved HTTP Method" }
func (httpMethodExposureDetector) Description() string {
	return "Reports an HTTP method an API document declares but that was never actually observed."
}
func (httpMethodExposureDetector) Version() int                 { return 1 }
func (httpMethodExposureDetector) Category() detection.Category { return detection.CategoryAPI }
func (httpMethodExposureDetector) Mode() detection.DetectorMode { return detection.DetectorPassive }

func (d httpMethodExposureDetector) Detect(_ context.Context, input detection.Input) ([]detection.Finding, error) {
	var findings []detection.Finding
	for _, ep := range input.Endpoints {
		if !ep.Documented || ep.Observed || ep.Method == "GET" || ep.Method == "" {
			continue
		}
		id := ep.ID
		findings = append(findings, detection.Finding{
			EndpointID: &id, DetectorID: d.ID(), DetectorVersion: d.Version(),
			Title:       "Documented " + ep.Method + " method never confirmed",
			Description: "API documentation declares " + ep.Method + " " + endpointLabel(ep) + ", but this platform has never actually observed a real response for it — this is a documented capability, not a confirmed or exploitable one.",
			Category:    detection.CategoryAPI, Scope: detection.ScopeEndpoint,
			Severity: detection.SeverityInformational, Confidence: 0.6,
			Evidence: []detection.Evidence{detection.NewEvidence(detection.EvidenceOpenAPIMeta, map[string]any{
				"url": endpointLabel(ep), "method": ep.Method, "documented": true, "observed": false,
			}, 0.6)},
			Remediation: "Confirm this documented method enforces the same authentication/authorization as the rest of the API before relying on documentation alone.",
		})
	}
	return findings, nil
}
