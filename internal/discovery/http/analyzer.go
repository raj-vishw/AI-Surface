package http

import (
	"encoding/json"
	"strings"

	"ai-surface-platform/internal/discovery/model"
	"ai-surface-platform/internal/httpclient"
)

// healthPaths are normalized paths treated as health-check endpoints.
var healthPaths = map[string]bool{"/health": true, "/healthz": true, "/ready": true, "/status": true}

// docPaths are normalized paths treated as API documentation endpoints.
var docPaths = map[string]bool{"/openapi.json": true, "/swagger.json": true}

// Analysis is the result of analyzing one HTTP response.
type Analysis struct {
	ServiceType model.ServiceType
	Indicators  []string
	IsJSON      bool
	// JSONBody is the top-level decoded JSON object when the response is
	// JSON and its root is an object; nil otherwise (not JSON, invalid
	// JSON, or a JSON array/scalar at the root).
	JSONBody map[string]any
}

// Analyze classifies resp using only observable evidence — status code,
// content type, the request path, and (for JSON object responses)
// top-level field names. It never attempts to identify a specific
// product/vendor/model (phase3.md §16) — see ClassifyAICandidate for the
// separate, still evidence-only "AI candidate" signal.
func Analyze(path string, resp *httpclient.Response) Analysis {
	var indicators []string
	contentType := strings.ToLower(resp.ContentType)
	isJSON := strings.Contains(contentType, "application/json") || strings.Contains(contentType, "+json")

	var jsonBody map[string]any
	if isJSON && len(resp.Body) > 0 {
		var decoded any
		if err := json.Unmarshal(resp.Body, &decoded); err == nil {
			if obj, ok := decoded.(map[string]any); ok {
				jsonBody = obj
			}
		}
	}

	serviceType := model.ServiceUnknown

	switch {
	case docPaths[path]:
		serviceType = model.ServiceDocumentation
		indicators = append(indicators, "path matches a known API documentation endpoint ("+path+")")
	case healthPaths[path] && resp.StatusCode < 400:
		serviceType = model.ServiceHealthEndpoint
		indicators = append(indicators, "path matches a known health-check endpoint ("+path+")")
	case isJSON && jsonBody != nil:
		serviceType = model.ServiceJSONAPI
		indicators = append(indicators, "response content-type is JSON and the body is a JSON object")
	case isJSON:
		serviceType = model.ServiceAPI
		indicators = append(indicators, "response content-type is JSON")
	case strings.Contains(contentType, "text/html"):
		serviceType = model.ServiceWebApplication
		indicators = append(indicators, "response content-type is text/html")
	}

	return Analysis{ServiceType: serviceType, Indicators: indicators, IsJSON: isJSON, JSONBody: jsonBody}
}
