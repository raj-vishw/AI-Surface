package http

import (
	"net/url"
	"strings"
)

// ScopeValidator decides whether a candidate/redirect URL is within an
// authorized target's scope. It is consulted twice: once for every
// generated candidate before it is requested (see GenerateCandidates), and
// once per redirect hop (wired into httpclient.Options.AllowRedirectTo) —
// so an out-of-scope host is never connected to, whether reached directly
// or via a redirect.
//
// Subdomain behavior (phase3.md §11 requires this be documented): a
// candidate is in scope if its host is an exact, case-insensitive match
// for the target host, OR if it is a strict subdomain of the target host
// (host == "sub." + targetHost). This means a target of "example.test"
// implicitly allows "api.example.test" but never "evil.example.net", and
// never a superstring collision like "notexample.test" (the match is on
// the "."-delimited label boundary, not a raw suffix/substring). Phase 3
// itself never generates a subdomain candidate on its own — this rule
// exists so a redirect to a same-organization subdomain the target server
// itself issues is not needlessly blocked, not to expand what discovery
// actively probes.
type ScopeValidator struct {
	host string // lowercase target host, no port
}

// NewScopeValidator builds a ScopeValidator scoped to targetURL's host.
func NewScopeValidator(targetURL string) (*ScopeValidator, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	return &ScopeValidator{host: strings.ToLower(u.Hostname())}, nil
}

// Allowed reports whether candidate is within scope: same host as the
// target, or a strict subdomain of it. See the subdomain-behavior
// documentation on ScopeValidator.
func (v *ScopeValidator) Allowed(candidate *url.URL) bool {
	if v == nil || candidate == nil {
		return false
	}
	host := strings.ToLower(candidate.Hostname())
	if host == "" {
		return false
	}
	if host == v.host {
		return true
	}
	return strings.HasSuffix(host, "."+v.host)
}

// AllowedURL is a convenience wrapper for Allowed that parses raw first.
func (v *ScopeValidator) AllowedURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return v.Allowed(u)
}
