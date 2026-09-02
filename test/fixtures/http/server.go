// Package httpfixture provides a deterministic, fully local HTTP server
// used by internal/discovery/http and internal/discovery/service's tests
// (unit and integration) and by the Phase 3 manual verification
// walkthrough. It never talks to the network beyond its own listener —
// phase3.md §33 explicitly requires tests not depend on external
// services.
package httpfixture

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
)

// Server is the fixture HTTP service. Its handlers cover every scenario
// phase3.md §33/§34 asks for: an ordinary web page, a JSON API doc, an
// AI-like (OpenAI-compatible-shaped, but never claiming to BE OpenAI —
// phase3.md §34) API, a health check, a redirect (in-scope by default,
// steerable out of scope via ?to=), an oversized response, and an HTTP
// error.
type Server struct {
	mu                sync.RWMutex
	modelsResponse    map[string]any
	fingerprintServer string // Server header served by /fingerprint-target; "nginx/1.25.3" until SetFingerprintServerHeader changes it
	httpServer        *httptest.Server
}

// New starts a Server on an OS-assigned ephemeral port and returns
// immediately — the caller must Close it.
func New() *Server {
	s := newUnstarted()
	s.httpServer = httptest.NewServer(s.mux())
	return s
}

// NewOnPort starts a Server on a specific, caller-chosen port (used by the
// standalone fixture binary — cmd/fixtureserver — for manual testing,
// where a predictable port is needed to pass to `ai-recon scan --target`).
func NewOnPort(port int) (*Server, error) {
	s := newUnstarted()
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

func newUnstarted() *Server {
	return &Server{modelsResponse: defaultModelsResponse(), fingerprintServer: "nginx/1.25.3"}
}

func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/openapi.json", s.handleOpenAPI)
	mux.HandleFunc("/v1/models", s.handleModels)
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/redirect", s.handleRedirect)
	mux.HandleFunc("/large-response", s.handleLargeResponse)
	mux.HandleFunc("/error", s.handleError)
	mux.HandleFunc("/fingerprint-target", s.handleFingerprintTarget)
	return mux
}

// URL returns the fixture's base URL (e.g. "http://127.0.0.1:54321").
func (s *Server) URL() string { return s.httpServer.URL }

// Close shuts the fixture down. Safe to call once per Server.
func (s *Server) Close() { s.httpServer.Close() }

// SetModelsResponse replaces the /v1/models JSON body at runtime, for the
// "response changes between scans" test (phase3.md §38): the endpoint's
// identity (method + normalized URL) is unchanged, only its content — and
// therefore its response hash — changes.
func (s *Server) SetModelsResponse(resp map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.modelsResponse = resp
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "fixture-web/1.0")
	_, _ = fmt.Fprint(w, "<html><body><h1>Fixture Web Service</h1></body></html>")
}

// handleFingerprintTarget serves a response shaped for Phase 6's
// integration tests (test/integration/fingerprint_persistence_test.go):
// realistic, multi-technology-corroborating headers and a session cookie
// — additive to this fixture, no existing route/behavior is touched.
func (s *Server) handleFingerprintTarget(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	server := s.fingerprintServer
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Powered-By", "Express")
	if server != "" {
		// Via is only sent alongside a Server value — an empty
		// fingerprintServer means "simulate nginx being entirely
		// replaced/removed", not just its version header disappearing,
		// for the fingerprint-removed integration test.
		w.Header().Set("Server", server)
		w.Header().Set("Via", "1.1 nginx")
	}
	http.SetCookie(w, &http.Cookie{
		Name: "JSESSIONID", Value: "synthetic-test-value", Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	_, _ = fmt.Fprint(w, "<html><body><h1>Fingerprint Fixture</h1></body></html>")
}

// SetFingerprintServerHeader replaces the Server (and, together, Via)
// header(s) /fingerprint-target serves — "" serves neither, simulating
// nginx being entirely replaced/removed rather than merely changing
// version — for Phase 6's change-detection integration tests (phase6.md
// §23), the same "mutate a fixture's response at runtime, identity
// unchanged" pattern SetModelsResponse established for Phase 3.
func (s *Server) SetFingerprintServerHeader(server string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fingerprintServer = server
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": "Fixture API", "version": "1.0.0"},
		"paths":   map[string]any{},
	})
}

func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	resp := s.modelsResponse
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, resp)
}

// defaultModelsResponse is an OpenAI-compatible-*shaped* /v1/models
// response. It is ONLY a test fixture (phase3.md §34) — the discovery
// engine under test must classify this as an AI endpoint candidate based
// on its shape, and must never claim it is actually OpenAI.
func defaultModelsResponse() map[string]any {
	return map[string]any{
		"object": "list",
		"data": []any{
			map[string]any{"id": "test-model", "object": "model", "created": 1700000000},
		},
	}
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "test-response",
		"object":  "chat.completion",
		"model":   "test-model",
		"created": 1700000000,
		"choices": []any{},
		"usage":   map[string]any{"prompt_tokens": 1, "completion_tokens": 1},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleRedirect issues a 302 to ?to=<url>, or back to this fixture's own
// root if to is omitted — i.e. in-scope by default. Tests exercising
// out-of-scope redirect handling pass the URL of a second, independent
// Server as ?to=, keeping everything local (phase3.md §33).
func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("to")
	if target == "" {
		target = s.URL() + "/"
	}
	http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // this fixture's entire purpose is a caller-controlled open redirect, for exercising discovery's own scope validation against it
}

// handleLargeResponse writes well over the platform's default 10 MiB
// response-size limit, entirely locally, so response-too-large handling
// can be tested without depending on any real oversized Internet resource.
func (s *Server) handleLargeResponse(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = 'a'
	}
	for i := 0; i < 200; i++ { // 200 * 64KiB = 12.5 MiB
		_, _ = w.Write(chunk)
	}
}

func (s *Server) handleError(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = fmt.Fprint(w, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
