package endpoint

import "regexp"

// Confidence tiers for JavaScript-sourced candidates (phase7.md §15):
// contextual API-client call sites are strong evidence; a bare string
// literal that merely looks path-shaped is weak evidence — plenty of
// JavaScript files contain unrelated strings, comments, test fixtures,
// and third-party URLs that are not real application routes.
const (
	// ConfidenceJSAPICall is used for a path literal that is the
	// argument to fetch(...)/axios(...)/.open(...) — a genuine API
	// client call site (phase7.md §15's own worked example: "discovered
	// as fetch() URL: confidence = 0.75").
	ConfidenceJSAPICall = 0.75
	// ConfidenceJSStringLiteral is used for a path-shaped string literal
	// with no corroborating call-site context (phase7.md §15's own
	// worked example: "discovered via JavaScript string: confidence =
	// 0.30").
	ConfidenceJSStringLiteral = 0.30
)

// jsQuote matches any of the three JavaScript string delimiters.
const jsQuote = "['\"`]"

// fetchAxiosPattern matches fetch(...)/axios(...)/axios.get(...)-shaped
// calls whose first argument is a string literal — a strong, contextual
// signal (phase7.md §15).
var fetchAxiosPattern = regexp.MustCompile(
	`(?:\bfetch|\baxios(?:\.(?:get|post|put|patch|delete|request))?)\s*\(\s*` + jsQuote + `([^'"` + "`" + `]{1,512})` + jsQuote,
)

// xhrOpenPattern matches XMLHttpRequest's classic
// `.open("METHOD", "url")` call shape.
var xhrOpenPattern = regexp.MustCompile(
	`\.open\s*\(\s*` + jsQuote + `\w+` + jsQuote + `\s*,\s*` + jsQuote + `([^'"` + "`" + `]{1,512})` + jsQuote,
)

// pathLikeStringPattern matches any quoted string literal that merely
// starts with "/" and looks path-shaped — the weak, uncorroborated
// fallback signal.
var pathLikeStringPattern = regexp.MustCompile(
	jsQuote + `(/[a-zA-Z0-9_][a-zA-Z0-9_\-./{}]{1,254})` + jsQuote,
)

// ExtractJSRoutes performs conservative, static (never executed) text
// analysis of source (one JavaScript file's or inline <script> block's
// content) and returns candidate endpoint paths with confidence
// reflecting how strong the surrounding context is (phase7.md §14/§15).
// Duplicate candidates (same path, same tier) are collapsed to one.
func ExtractJSRoutes(source string) []Candidate {
	seen := make(map[string]bool)
	var out []Candidate

	add := func(path string, confidence float64, evidence string) {
		path = sanitizeJSPath(path)
		if path == "" || !looksLikeRoute(path) {
			return
		}
		key := path
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Candidate{
			URL: path, Method: "GET", Source: "javascript", Confidence: confidence,
			Inferred: confidence < 0.5, Evidence: evidence,
		})
	}

	for _, m := range fetchAxiosPattern.FindAllStringSubmatch(source, -1) {
		add(m[1], ConfidenceJSAPICall, truncateEvidence(m[0]))
	}
	for _, m := range xhrOpenPattern.FindAllStringSubmatch(source, -1) {
		add(m[1], ConfidenceJSAPICall, truncateEvidence(m[0]))
	}
	for _, m := range pathLikeStringPattern.FindAllStringSubmatch(source, -1) {
		// Only add as the weak fallback if not already found via a
		// strong call-site match above — a candidate is never
		// double-added at two different confidences (phase7.md §9's
		// "do not double-count" principle applied here too).
		path := sanitizeJSPath(m[1])
		if path == "" || seen[path] {
			continue
		}
		add(m[1], ConfidenceJSStringLiteral, "string literal: \""+m[1]+"\"")
	}

	return out
}

// sanitizeJSPath drops a query string/fragment (kept separately by the
// caller's own normalization pass, not here) and rejects anything that
// isn't a bare, absolute path.
func sanitizeJSPath(path string) string {
	for i, c := range path {
		if c == '?' || c == '#' {
			path = path[:i]
			break
		}
	}
	if path == "" || path[0] != '/' {
		return ""
	}
	return path
}

// looksLikeRoute filters out common false positives (phase7.md §15):
// bare "/", template-literal placeholders with no real content, and
// anything containing whitespace (never a valid URL path).
func looksLikeRoute(path string) bool {
	if path == "/" || len(path) < 2 {
		return false
	}
	for _, c := range path {
		if c == ' ' || c == '\t' || c == '\n' {
			return false
		}
	}
	return true
}

func truncateEvidence(s string) string {
	const maxEvidenceLen = 120
	if len(s) > maxEvidenceLen {
		return s[:maxEvidenceLen] + "…"
	}
	return s
}
