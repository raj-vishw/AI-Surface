package endpoint

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		contentType string
		wantClass   Classification
		wantType    string
		wantVersion string
	}{
		{"root page", "/", "text/html", ClassPage, "", ""},
		{"graphql", "/graphql", "application/json", ClassGraphQL, "graphql", ""},
		{"openapi json", "/openapi.json", "application/json", ClassOpenAPI, "openapi", ""},
		{"swagger json", "/swagger.json", "application/json", ClassSwagger, "swagger", ""},
		{"api docs", "/api-docs", "text/html", ClassSwagger, "swagger", ""},
		{"docs", "/docs", "text/html", ClassDocumentation, "", ""},
		{"sitemap", "/sitemap.xml", "application/xml", ClassSitemap, "", ""},
		{"robots", "/robots.txt", "text/plain", ClassRobots, "", ""},
		{"login", "/login", "text/html", ClassAuth, "", ""},
		{"oauth token", "/oauth/token", "application/json", ClassAuth, "", ""},
		{"static js", "/static/app.js", "application/javascript", ClassStatic, "", ""},
		{"versioned api", "/api/v1/users", "application/json", ClassAPI, "rest", "v1"},
		{"bare api", "/api/users", "application/json", ClassAPI, "rest", ""},
		{"unversioned rest by content-type", "/users", "application/json", ClassAPI, "rest", ""},
		{"unknown", "/some/random/thing", "text/plain", ClassUnknown, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, apiType, version := Classify(tc.path, tc.contentType)
			if class != tc.wantClass {
				t.Errorf("Classify(%q) class = %s, want %s", tc.path, class, tc.wantClass)
			}
			if apiType != tc.wantType {
				t.Errorf("Classify(%q) apiType = %q, want %q", tc.path, apiType, tc.wantType)
			}
			if version != tc.wantVersion {
				t.Errorf("Classify(%q) apiVersion = %q, want %q", tc.path, version, tc.wantVersion)
			}
		})
	}
}

func TestIsAICandidatePath(t *testing.T) {
	positive := []string{"/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/api/generate", "/api/chat"}
	for _, p := range positive {
		if !IsAICandidatePath(p) {
			t.Errorf("IsAICandidatePath(%q) = false, want true", p)
		}
	}
	negative := []string{"/api/users", "/login", "/v1/orders"}
	for _, p := range negative {
		if IsAICandidatePath(p) {
			t.Errorf("IsAICandidatePath(%q) = true, want false", p)
		}
	}
}

func TestIsWebSocketCandidate(t *testing.T) {
	if !IsWebSocketCandidate("wss://example.test/socket") {
		t.Error("expected wss:// to be a websocket candidate")
	}
	if !IsWebSocketCandidate("ws://example.test/socket") {
		t.Error("expected ws:// to be a websocket candidate")
	}
	if IsWebSocketCandidate("https://example.test/socket") {
		t.Error("expected https:// to not be a websocket candidate")
	}
}
