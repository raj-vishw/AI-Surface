package endpoint

import (
	"regexp"
	"strings"
)

// apiPathPattern recognizes common REST/RPC-shaped API path prefixes
// (phase7.md §16) — evidence toward, never proof of, an API
// classification.
var apiPathPattern = regexp.MustCompile(`(?i)^/(api|rest|rpc|json|services)(/|$)`)

// versionSegmentPattern extracts an explicit version segment like
// "/api/v1/users" -> "v1", "/v2/models" -> "v2" (phase7.md §17). Never
// inferred from anything else — a path with no such segment has no
// detected version.
var versionSegmentPattern = regexp.MustCompile(`(?i)/v([0-9]+(\.[0-9]+)?)(/|$)`)

// authPathFragments name likely-authentication path segments (phase7.md
// §33) — classification only, never an attempt to authenticate.
var authPathFragments = []string{
	"/login", "/signin", "/sign-in", "/logout", "/signout", "/sign-out",
	"/register", "/signup", "/sign-up", "/auth/", "/oauth/", "/sso/",
}

// staticExtensions name file extensions treated as static assets rather
// than application endpoints (phase7.md §35).
var staticExtensions = []string{
	".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".webp", ".pdf", ".zip",
}

// aiAPIPathPattern recognizes AI-oriented endpoint path shapes (phase7.md
// §50) — a candidate only, never a claim that a specific provider or
// model is present. Phase 6 fingerprint evidence, when available, is
// consulted separately by the service layer to corroborate this (see
// api.go's doc comment).
var aiAPIPathPattern = regexp.MustCompile(`(?i)^/(v[0-9]+/(models|chat/completions|completions|embeddings|responses)|api/(models|inference|generate|chat|embeddings))(/|$)`)

// graphQLPathPattern recognizes a GraphQL endpoint path (phase7.md §18).
var graphQLPathPattern = regexp.MustCompile(`(?i)^/graphql/?$`)

// websocketSchemePattern recognizes an explicit ws:// or wss:// URL
// (phase7.md §34).
var websocketSchemePattern = regexp.MustCompile(`(?i)^wss?://`)

// Classify determines an endpoint's Classification and, where evidence
// supports it, APIType/APIVersion, from its normalized path and content
// type — never from guessing (phase7.md §32). classification is always
// set (ClassUnknown is an acceptable, honest answer); apiType/apiVersion
// are "" when there's no supporting evidence.
func Classify(path, contentType string) (classification Classification, apiType, apiVersion string) {
	lowerPath := strings.ToLower(path)

	switch {
	case graphQLPathPattern.MatchString(path):
		return ClassGraphQL, "graphql", ""
	case isOpenAPIPath(lowerPath):
		return ClassOpenAPI, "openapi", apiVersionFromPath(path)
	case isSwaggerPath(lowerPath):
		return ClassSwagger, "swagger", apiVersionFromPath(path)
	case isDocumentationPath(lowerPath):
		return ClassDocumentation, "", ""
	case path == "/sitemap.xml" || strings.HasSuffix(lowerPath, "sitemap.xml"):
		return ClassSitemap, "", ""
	case path == "/robots.txt":
		return ClassRobots, "", ""
	case isAuthPath(lowerPath):
		return ClassAuth, "", ""
	case isStaticPath(lowerPath):
		return ClassStatic, "", ""
	case apiPathPattern.MatchString(path):
		return ClassAPI, "rest", apiVersionFromPath(path)
	case looksLikeJSON(contentType):
		return ClassAPI, "rest", apiVersionFromPath(path)
	case path == "/" || strings.HasSuffix(lowerPath, ".html") || strings.HasSuffix(lowerPath, ".htm") || looksLikeHTML(contentType):
		return ClassPage, "", ""
	default:
		return ClassUnknown, "", ""
	}
}

func apiVersionFromPath(path string) string {
	m := versionSegmentPattern.FindStringSubmatch(path)
	if m == nil {
		return ""
	}
	return "v" + m[1]
}

func isOpenAPIPath(lowerPath string) bool {
	switch lowerPath {
	case "/openapi.json", "/openapi.yaml", "/openapi.yml", "/v3/api-docs":
		return true
	}
	return strings.HasSuffix(lowerPath, "/openapi.json") || strings.HasSuffix(lowerPath, "/v3/api-docs")
}

func isSwaggerPath(lowerPath string) bool {
	switch lowerPath {
	case "/swagger.json", "/swagger.yaml", "/swagger", "/swagger/", "/api-docs":
		return true
	}
	return strings.Contains(lowerPath, "/swagger")
}

func isDocumentationPath(lowerPath string) bool {
	return strings.Contains(lowerPath, "/docs") || strings.Contains(lowerPath, "/redoc") || strings.Contains(lowerPath, "/documentation")
}

func isAuthPath(lowerPath string) bool {
	for _, frag := range authPathFragments {
		if strings.Contains(lowerPath, frag) {
			return true
		}
	}
	return false
}

func isStaticPath(lowerPath string) bool {
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return strings.HasPrefix(lowerPath, "/static/") || strings.HasPrefix(lowerPath, "/assets/")
}

func looksLikeJSON(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "json")
}

func looksLikeHTML(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "html")
}

// IsAICandidatePath reports whether path matches a known AI-oriented API
// shape (phase7.md §50) — a candidate signal only.
func IsAICandidatePath(path string) bool {
	return aiAPIPathPattern.MatchString(path)
}

// IsWebSocketCandidate reports whether rawURL explicitly uses the ws/wss
// scheme (phase7.md §34).
func IsWebSocketCandidate(rawURL string) bool {
	return websocketSchemePattern.MatchString(rawURL)
}
