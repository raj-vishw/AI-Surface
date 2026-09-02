package fingerprint

import "strings"

// technologyAliases maps a lowercased, loosely-formatted variant to its
// canonical technology identity (phase6.md §11) — "Nginx", "nginx",
// "nginx/1.25" (the version is stripped before lookup, see
// NormalizeTechnology), and "nginx web server" all resolve to "nginx".
// Deliberately a small, explicit, reviewable table rather than a fuzzy-
// matching heuristic — false-positive normalization (silently merging two
// actually-different technologies) would be worse than an unnormalized
// duplicate.
var technologyAliases = map[string]string{
	"nginx":               "nginx",
	"nginx web server":    "nginx",
	"apache":              "Apache",
	"apache httpd":        "Apache",
	"apache/2":            "Apache",
	"next":                "Next.js",
	"next.js":             "Next.js",
	"nextjs":              "Next.js",
	"react":               "React",
	"reactjs":             "React",
	"react.js":            "React",
	"vue":                 "Vue.js",
	"vue.js":              "Vue.js",
	"vuejs":               "Vue.js",
	"angular":             "Angular",
	"angularjs":           "Angular",
	"wordpress":           "WordPress",
	"drupal":              "Drupal",
	"express":             "Express",
	"expressjs":           "Express",
	"express.js":          "Express",
	"django":              "Django",
	"flask":               "Flask",
	"laravel":             "Laravel",
	"rails":               "Ruby on Rails",
	"ruby on rails":       "Ruby on Rails",
	"asp.net":             "ASP.NET",
	"aspnet":              "ASP.NET",
	"spring":              "Spring",
	"fastapi":             "FastAPI",
	"node":                "Node.js",
	"node.js":             "Node.js",
	"nodejs":              "Node.js",
	"php":                 "PHP",
	"cloudflare":          "Cloudflare",
	"fastly":              "Fastly",
	"akamai":              "Akamai",
	"aws":                 "AWS",
	"amazon web services": "AWS",
	"azure":               "Azure",
	"microsoft azure":     "Azure",
	"google cloud":        "Google Cloud",
	"gcp":                 "Google Cloud",
	"openai":              "OpenAI",
	"anthropic":           "Anthropic",
	"mysql":               "MySQL",
	"postgresql":          "PostgreSQL",
	"postgres":            "PostgreSQL",
	"redis":               "Redis",
	"mongodb":             "MongoDB",
	"mongo":               "MongoDB",
}

// NormalizeTechnology returns raw's canonical technology identity
// (phase6.md §11). It strips a trailing "/<version>" or " <version>"
// suffix before lookup (so "nginx/1.25.3" and "nginx" normalize
// identically — version is a separate, explicitly-extracted field, never
// folded into the technology name), then consults technologyAliases. If
// raw has no known alias, it is returned trimmed and with its original
// casing preserved (an unknown technology is not forced through any
// casing convention) — normalization only merges *known* variants, it
// never invents an identity for a technology this package doesn't
// recognize.
func NormalizeTechnology(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	key := strings.ToLower(stripVersionSuffix(trimmed))
	if canonical, ok := technologyAliases[key]; ok {
		return canonical
	}
	return trimmed
}

// stripVersionSuffix removes a trailing "/1.2.3"-shaped or " 1.2.3"-shaped
// version token, if present.
func stripVersionSuffix(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 && looksLikeVersion(s[i+1:]) {
		return s[:i]
	}
	if i := strings.LastIndexByte(s, ' '); i >= 0 && looksLikeVersion(s[i+1:]) {
		return s[:i]
	}
	return s
}

func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	hasDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '.':
			// allowed
		default:
			return false
		}
	}
	return hasDigit
}
