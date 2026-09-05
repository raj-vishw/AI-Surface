package intelligence

import (
	"net/url"
	"strings"
)

// Normalize canonicalizes i's Value according to its Type (phase10.md
// §17/§56). It is idempotent: Normalize(Normalize(i)) == Normalize(i).
// Normalization never destroys a meaningful distinction — a URL's path,
// query, and port are preserved, only the host is case-folded
// (phase10.md §56).
func Normalize(i Indicator) Indicator {
	switch i.Type {
	case IndicatorDomain, IndicatorSubdomain, IndicatorHostname:
		return Indicator{Type: i.Type, Value: NormalizeDomain(i.Value)}
	case IndicatorIPv4, IndicatorIPv6:
		return Indicator{Type: i.Type, Value: NormalizeIP(i.Value)}
	case IndicatorURL:
		return Indicator{Type: i.Type, Value: normalizeURL(i.Value)}
	case IndicatorHash:
		return Indicator{Type: i.Type, Value: strings.ToLower(strings.TrimSpace(i.Value))}
	case IndicatorTechnology, IndicatorCertificate:
		return Indicator{Type: i.Type, Value: strings.TrimSpace(i.Value)}
	default:
		return Indicator{Type: i.Type, Value: strings.TrimSpace(i.Value)}
	}
}

// normalizeURL lowercases the scheme and host, and removes a default
// port (80 for http, 443 for https) — path, query (including parameter
// names/values), and any non-default port are left untouched, since they
// are part of what makes one URL indicator distinct from another
// (phase10.md §56).
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch {
	case u.Scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	case u.Scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	}
	u.Host = host
	return u.String()
}
