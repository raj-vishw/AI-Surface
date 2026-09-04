// Package endpointfixture provides a deterministic, fully local HTTP
// server used by internal/discovery/endpoint's tests (unit and
// integration) and the Phase 7 manual verification walkthrough. It never
// talks to the network beyond its own listener — the same "no external
// dependency" discipline every fixture in this project follows
// (phase7.md §66).
package endpointfixture

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
)

// Server is the fixture HTTP service. Its routes cover every scenario
// phase7.md §66 asks for: HTML links (including duplicates and a cycle),
// a form, JavaScript with API calls, JSON API responses, an OpenAPI
// document, a Swagger document, robots.txt, sitemap.xml, a redirect, an
// external-domain reference, dynamic-ID paths, and a query-parameter
// endpoint.
type Server struct {
	httpServer *httptest.Server
}

// New starts a Server on an OS-assigned ephemeral port and returns
// immediately — the caller must Close it.
func New() *Server {
	s := &Server{}
	s.httpServer = httptest.NewServer(s.mux())
	return s
}

// NewOnPort starts a Server on a specific, caller-chosen port (for manual
// testing, where a predictable port is useful).
func NewOnPort(port int) (*Server, error) {
	s := &Server{}
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	s.httpServer = httptest.NewUnstartedServer(s.mux())
	s.httpServer.Listener.Close() //nolint:errcheck,gosec // replacing the ephemeral listener with our fixed one below
	s.httpServer.Listener = listener
	s.httpServer.Start()
	return s, nil
}

// URL returns the fixture's base URL (e.g. "http://127.0.0.1:54321").
func (s *Server) URL() string { return s.httpServer.URL }

// Close shuts the fixture down. Safe to call once per Server.
func (s *Server) Close() { s.httpServer.Close() }

func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/about", s.handleAbout)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/api/users", s.handleAPIUsers)
	mux.HandleFunc("/api/v1/users", s.handleAPIV1Users)
	mux.HandleFunc("/api/v1/models", s.handleAPIV1Models)
	mux.HandleFunc("/graphql", s.handleGraphQL)
	mux.HandleFunc("/openapi.json", s.handleOpenAPI)
	mux.HandleFunc("/swagger.json", s.handleSwagger)
	mux.HandleFunc("/robots.txt", s.handleRobots)
	mux.HandleFunc("/sitemap.xml", s.handleSitemap)
	mux.HandleFunc("/static/app.js", s.handleAppJS)
	mux.HandleFunc("/redirect", s.handleRedirect)
	mux.HandleFunc("/external-link", s.handleExternalLink)
	mux.HandleFunc("/a", s.handleCycleA)
	mux.HandleFunc("/b", s.handleCycleB)
	mux.HandleFunc("/users/", s.handleUserByID)
	return mux
}

func html(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, "<!DOCTYPE html><html><body>"+body+"</body></html>")
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// handleRoot links to /about (twice, to exercise duplicate-link dedup),
// /login, /api/users, /users/123 (dynamic ID), the app.js script, and
// /external-link.
func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	html(w, `
		<h1>Fixture Home</h1>
		<a href="/about">About</a>
		<a href="/about">About again (duplicate)</a>
		<a href="/login">Login</a>
		<a href="/api/users">Users API</a>
		<a href="/users/123">User 123</a>
		<a href="/external-link">External</a>
		<a href="/a">Cycle start</a>
		<script src="/static/app.js"></script>
	`)
}

// handleAbout links back to / and to /a — part of the cycle-detection
// fixture (a real page linking into the a<->b cycle, plus a self-cycle
// back to root).
func (s *Server) handleAbout(w http.ResponseWriter, _ *http.Request) {
	html(w, `<h1>About</h1><a href="/">Home</a><a href="/a">A</a>`)
}

func (s *Server) handleCycleA(w http.ResponseWriter, _ *http.Request) {
	html(w, `<h1>A</h1><a href="/b">B</a>`)
}

func (s *Server) handleCycleB(w http.ResponseWriter, _ *http.Request) {
	html(w, `<h1>B</h1><a href="/a">A</a>`)
}

// handleLogin serves a POST form (username/password) — never submitted
// by the crawler, only discovered (phase7.md §13).
func (s *Server) handleLogin(w http.ResponseWriter, _ *http.Request) {
	html(w, `
		<h1>Login</h1>
		<form method="POST" action="/login">
			<input type="text" name="username">
			<input type="password" name="password">
		</form>
	`)
}

func (s *Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"users": []map[string]any{{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}},
		"page":  r.URL.Query().Get("page"),
	})
}

func (s *Server) handleAPIV1Users(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"users": []string{"alice", "bob"}})
}

// handleAPIV1Models serves an AI-shaped API response, including an
// explicit model identifier — phase7.md §51: only ever *recorded* if
// present, never queried for.
func (s *Server) handleAPIV1Models(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"data": []map[string]any{{"id": "fixture-model-v1", "object": "model"}},
	})
}

func (s *Server) handleGraphQL(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"data": nil})
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": "Fixture API", "version": "1.0.0"},
		"paths": map[string]any{
			"/api/users": map[string]any{
				"get":  map[string]any{"operationId": "listUsers", "tags": []string{"users"}},
				"post": map[string]any{"operationId": "createUser"},
			},
			"/api/users/{id}": map[string]any{
				"get":    map[string]any{"operationId": "getUser", "parameters": []map[string]any{{"name": "id", "in": "path"}}},
				"delete": map[string]any{"operationId": "deleteUser"},
			},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{"type": "http", "scheme": "bearer"},
			},
		},
	})
}

func (s *Server) handleSwagger(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"swagger": "2.0",
		"info":    map[string]any{"version": "1.0.0"},
		"paths": map[string]any{
			"/api/legacy": map[string]any{
				"get": map[string]any{"operationId": "legacyList"},
			},
		},
		"securityDefinitions": map[string]any{
			"apiKeyAuth": map[string]any{"type": "apiKey", "in": "header", "name": "X-API-Key"},
		},
	})
}

func (s *Server) handleRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	base := s.httpServer.URL
	_, _ = fmt.Fprintf(w, "User-agent: *\nDisallow: /admin\nAllow: /api/users\nSitemap: %s/sitemap.xml\n", base)
}

func (s *Server) handleSitemap(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	base := s.httpServer.URL
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>%s/</loc></url>
  <url><loc>%s/about</loc></url>
</urlset>`, base, base)
}

// handleAppJS serves JavaScript with a strong fetch()-based API
// reference, an axios reference, and a weak bare-string reference —
// exercising javascript.go's confidence tiers end to end.
func (s *Server) handleAppJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = fmt.Fprint(w, `
		fetch("/api/v1/users").then(r => r.json());
		axios.get("/api/v1/models");
		const weakRef = "/weak-endpoint-guess";
	`)
}

// handleRedirect issues an in-scope 302 to /about.
func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/about", http.StatusFound)
}

// handleExternalLink references an out-of-scope external domain — must
// be recorded as an external reference, never actually requested
// (phase7.md §55).
func (s *Server) handleExternalLink(w http.ResponseWriter, _ *http.Request) {
	html(w, `<h1>External</h1><a href="https://cdn.example.net/asset.js">External asset</a>`)
}

// handleUserByID serves both numeric-ID and named ("admin") user paths —
// /users/123, /users/456 (should template to /users/{id}), and
// /users/admin (must NOT be templated — phase7.md §38/§76).
func (s *Server) handleUserByID(w http.ResponseWriter, _ *http.Request) {
	html(w, `<h1>User</h1>`)
}
