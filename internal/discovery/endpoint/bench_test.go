package endpoint

import (
	"testing"

	domainendpoint "ai-recon-platform/internal/domain/endpoint"
)

// BenchmarkNormalize measures internal/domain/endpoint.Normalize's
// throughput — the identity/dedup path every discovered candidate goes
// through (phase7.md §80). No network I/O.
func BenchmarkNormalize(b *testing.B) {
	urls := []string{
		"https://EXAMPLE.test:443/API/Users/",
		"https://example.test/search?q=x&page=2",
		"http://example.test/a/../b/./c",
		"https://example.test/users/123",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = domainendpoint.Normalize(urls[i%len(urls)])
	}
}

// BenchmarkTemplatePath measures the path-parameter templating pass
// (phase7.md §38/§80).
func BenchmarkTemplatePath(b *testing.B) {
	paths := []string{
		"/users/123", "/users/admin", "/api/v1/orders/42/items/7",
		"/sessions/550e8400-e29b-41d4-a716-446655440000",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = TemplatePath(paths[i%len(paths)])
	}
}

// BenchmarkParseHTML measures HTML link/form extraction throughput
// (phase7.md §80).
func BenchmarkParseHTML(b *testing.B) {
	body := []byte(`<!DOCTYPE html><html><body>
		<a href="/about">About</a>
		<a href="/api/users">Users</a>
		<a href="/users/123">User</a>
		<script src="/static/app.js"></script>
		<link rel="stylesheet" href="/static/app.css">
		<form method="POST" action="/login">
			<input type="text" name="username">
			<input type="password" name="password">
		</form>
	</body></html>`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ParseHTML(body)
	}
}

// BenchmarkExtractJSRoutes measures JavaScript static route extraction
// throughput (phase7.md §80).
func BenchmarkExtractJSRoutes(b *testing.B) {
	source := `
		fetch("/api/users").then(r => r.json());
		axios.get("/api/v1/models");
		const xhr = new XMLHttpRequest();
		xhr.open("GET", "/auth/login");
		const weak = "/weak-guess";
	`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ExtractJSRoutes(source)
	}
}

// BenchmarkParseOpenAPI measures OpenAPI/Swagger document parsing
// throughput (phase7.md §80).
func BenchmarkParseOpenAPI(b *testing.B) {
	body := []byte(testOpenAPIJSON)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseOpenAPI(body)
	}
}

// BenchmarkAccumulator_Merge measures endpoint deduplication/
// corroboration-merging throughput (phase7.md §80) — many contributions
// to the same small set of logical endpoints, the realistic multi-source
// case (phase7.md §40).
func BenchmarkAccumulator_Merge(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		acc := newAccumulator(10000)
		for j := 0; j < 100; j++ {
			for _, source := range []string{"html", "javascript", "openapi"} {
				code := 200
				acc.Add(Result{
					URL: "https://example.test/api/users", Method: "GET",
					Sources: []string{source}, Confidence: 0.7, StatusCode: &code,
				})
			}
		}
	}
}
