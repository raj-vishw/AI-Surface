package endpoint

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

// defaultPorts maps a scheme to the port used when none is specified.
// Ports equal to a scheme's default are omitted from the canonical URL
// string (but always populated in Normalized.Port).
var defaultPorts = map[string]int{
	"http":  80,
	"https": 443,
}

// Normalized is the result of normalizing a raw URL. URL is the canonical
// form (scheme + host + optional non-default port + cleaned path only — no
// query string, no fragment): identity and deduplication are computed from
// exactly these fields, per the strategy documented in
// docs/architecture/asset-model.md.
//
// Trailing-slash policy: the canonical Path never ends in "/" unless it is
// the root path "/" itself, so "https://example.com/api" and
// "https://example.com/api/" normalize to the same identity.
type Normalized struct {
	Scheme       string
	Host         string
	Port         int
	Path         string
	QueryPattern string
	URL          string
}

// Normalize deterministically normalizes raw into its canonical form. It
// performs no network request — this is a pure string transformation.
//
// Rules applied:
//   - scheme and host are lowercased
//   - a missing path becomes "/"; the path is cleaned (. and .. resolved,
//     duplicate slashes collapsed) and, except for the root, any trailing
//     slash is removed
//   - the fragment is discarded entirely — it never reaches the server and
//     carries no identity information
//   - the port is resolved to an explicit value (scheme default if
//     unspecified) and stored in Port, but omitted from the canonical URL
//     string when it equals the scheme's default
//   - query parameter *names* (sorted, deduplicated) are kept as
//     QueryPattern; query parameter *values* are discarded entirely, since
//     they commonly carry session tokens, API keys, or other secrets that
//     must never be persisted (see internal/domain/asset's metadata
//     redaction for the same policy applied to metadata)
func Normalize(raw string) (Normalized, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Normalized{}, fmt.Errorf("parsing url: %w", err)
	}
	if u.Scheme == "" {
		return Normalized{}, fmt.Errorf("url %q has no scheme", raw)
	}
	if u.Host == "" {
		return Normalized{}, fmt.Errorf("url %q has no host", raw)
	}

	scheme := strings.ToLower(u.Scheme)
	host, port, err := resolveHostPort(u, scheme)
	if err != nil {
		return Normalized{}, err
	}

	cleanPath := normalizePath(u.Path)
	queryPattern := normalizeQueryPattern(u.RawQuery)

	canonical := &url.URL{Scheme: scheme, Host: hostForURL(host, port, scheme), Path: cleanPath}

	return Normalized{
		Scheme:       scheme,
		Host:         host,
		Port:         port,
		Path:         cleanPath,
		QueryPattern: queryPattern,
		URL:          canonical.String(),
	}, nil
}

func resolveHostPort(u *url.URL, scheme string) (host string, port int, err error) {
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", 0, fmt.Errorf("url has no hostname")
	}

	portStr := u.Port()
	if portStr == "" {
		defaultPort, ok := defaultPorts[scheme]
		if !ok {
			return "", 0, fmt.Errorf("scheme %q has no default port; an explicit port is required", scheme)
		}
		return hostname, defaultPort, nil
	}

	parsedPort, err := strconv.Atoi(portStr)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	return hostname, parsedPort, nil
}

// hostForURL renders host[:port], omitting the port when it matches the
// scheme's default so the canonical URL string doesn't carry redundant
// information (https://example.com, not https://example.com:443).
func hostForURL(host string, port int, scheme string) string {
	if defaultPort, ok := defaultPorts[scheme]; ok && port == defaultPort {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// normalizePath cleans p and applies the documented trailing-slash policy.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := path.Clean(p)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	if cleaned != "/" {
		cleaned = strings.TrimSuffix(cleaned, "/")
	}
	return cleaned
}

// normalizeQueryPattern returns the sorted, deduplicated, comma-joined set
// of query parameter names — never their values.
func normalizeQueryPattern(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) == 0 {
		return ""
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}
