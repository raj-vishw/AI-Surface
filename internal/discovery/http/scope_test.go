package http

import "testing"

func TestScopeValidator_SameHost(t *testing.T) {
	v := mustScope(t, "https://example.test")
	if !v.AllowedURL("https://example.test/api") {
		t.Error("same host should be allowed")
	}
}

func TestScopeValidator_AllowedSubdomain(t *testing.T) {
	v := mustScope(t, "https://example.test")
	if !v.AllowedURL("https://api.example.test/v1") {
		t.Error("a subdomain of the target host should be allowed")
	}
}

func TestScopeValidator_UnrelatedHost(t *testing.T) {
	v := mustScope(t, "https://example.test")
	if v.AllowedURL("https://evil.example.net/") {
		t.Error("an unrelated host must never be allowed")
	}
}

func TestScopeValidator_NoLabelBoundaryBypass(t *testing.T) {
	v := mustScope(t, "https://example.test")
	// "notexample.test" ends with "example.test" as a raw string suffix
	// but is not a subdomain of it (no "." label boundary) — must not
	// match.
	if v.AllowedURL("https://notexample.test/") {
		t.Error("a suffix match without a label boundary must not be treated as in-scope")
	}
}

func TestScopeValidator_CaseInsensitive(t *testing.T) {
	v := mustScope(t, "https://Example.Test")
	if !v.AllowedURL("https://EXAMPLE.test/") {
		t.Error("host matching should be case-insensitive")
	}
}

func TestScopeValidator_EmptyHostRejected(t *testing.T) {
	v := mustScope(t, "https://example.test")
	if v.Allowed(nil) {
		t.Error("a nil URL must never be allowed")
	}
	if v.AllowedURL("not a url") {
		t.Error("an unparseable URL must never be allowed")
	}
}

func TestScopeValidator_NilValidatorRejectsEverything(t *testing.T) {
	var v *ScopeValidator
	if v.AllowedURL("https://example.test/") {
		t.Error("a nil ScopeValidator must reject everything, not panic or allow")
	}
}
