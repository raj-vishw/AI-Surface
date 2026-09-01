package http

import (
	"testing"

	"ai-recon-platform/internal/discovery/model"
	"ai-recon-platform/internal/httpclient"
)

func TestAnalyze_JSONObject(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"a":1}`)}
	a := Analyze("/api/data", resp)
	if !a.IsJSON {
		t.Error("expected IsJSON true")
	}
	if a.JSONBody == nil {
		t.Error("expected JSONBody to be populated for a JSON object response")
	}
	if a.ServiceType != model.ServiceJSONAPI {
		t.Errorf("ServiceType = %s, want %s", a.ServiceType, model.ServiceJSONAPI)
	}
}

func TestAnalyze_HTML(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 200, ContentType: "text/html; charset=utf-8", Body: []byte("<html></html>")}
	a := Analyze("/", resp)
	if a.ServiceType != model.ServiceWebApplication {
		t.Errorf("ServiceType = %s, want %s", a.ServiceType, model.ServiceWebApplication)
	}
}

func TestAnalyze_PlainText(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 200, ContentType: "text/plain", Body: []byte("hello")}
	a := Analyze("/robots.txt", resp)
	if a.ServiceType != model.ServiceUnknown {
		t.Errorf("ServiceType = %s, want %s for plain text", a.ServiceType, model.ServiceUnknown)
	}
}

func TestAnalyze_EmptyResponse(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 204, ContentType: "", Body: nil}
	a := Analyze("/", resp)
	if a.ServiceType != model.ServiceUnknown {
		t.Errorf("ServiceType = %s, want %s for an empty response", a.ServiceType, model.ServiceUnknown)
	}
}

func TestAnalyze_HTTPErrorDoesNotCrash(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 500, ContentType: "text/plain", Body: []byte("internal error")}
	a := Analyze("/error", resp)
	if a.ServiceType != model.ServiceUnknown {
		t.Errorf("ServiceType = %s, want %s", a.ServiceType, model.ServiceUnknown)
	}
}

func TestAnalyze_DocumentationPath(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"openapi":"3.0.0"}`)}
	a := Analyze("/openapi.json", resp)
	if a.ServiceType != model.ServiceDocumentation {
		t.Errorf("ServiceType = %s, want %s", a.ServiceType, model.ServiceDocumentation)
	}
}

func TestAnalyze_HealthPath(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"status":"ok"}`)}
	a := Analyze("/health", resp)
	if a.ServiceType != model.ServiceHealthEndpoint {
		t.Errorf("ServiceType = %s, want %s", a.ServiceType, model.ServiceHealthEndpoint)
	}
}

func TestAnalyze_HealthPathIgnoredOnErrorStatus(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 503, ContentType: "application/json", Body: []byte(`{}`)}
	a := Analyze("/health", resp)
	if a.ServiceType == model.ServiceHealthEndpoint {
		t.Error("a failing (5xx) health check response should not be classified as a healthy HEALTH_ENDPOINT")
	}
}

func TestAnalyze_InvalidJSONBodyIsNotTreatedAsObject(t *testing.T) {
	resp := &httpclient.Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`not json`)}
	a := Analyze("/api/data", resp)
	if a.JSONBody != nil {
		t.Error("invalid JSON must not produce a JSONBody")
	}
	// content-type is still JSON, so this should classify as API (no
	// parsed object) rather than JSON_API.
	if a.ServiceType != model.ServiceAPI {
		t.Errorf("ServiceType = %s, want %s for JSON content-type with an unparsed body", a.ServiceType, model.ServiceAPI)
	}
}
