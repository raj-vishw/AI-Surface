package endpoint

import (
	"strings"
	"testing"
)

func TestNormalize_LowercasesSchemeAndHost(t *testing.T) {
	norm, err := Normalize("HTTPS://EXAMPLE.COM/Api")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.Scheme != "https" || norm.Host != "example.com" {
		t.Errorf("got scheme=%q host=%q, want https/example.com", norm.Scheme, norm.Host)
	}
}

func TestNormalize_DefaultPortOmittedFromURL(t *testing.T) {
	norm, err := Normalize("https://example.com:443/api")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.Port != 443 {
		t.Errorf("Port = %d, want 443 (explicit even though default)", norm.Port)
	}
	if norm.URL != "https://example.com/api" {
		t.Errorf("URL = %q, want default port omitted", norm.URL)
	}
}

func TestNormalize_NonDefaultPortKept(t *testing.T) {
	norm, err := Normalize("https://example.com:8443/api")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.URL != "https://example.com:8443/api" {
		t.Errorf("URL = %q, want non-default port preserved", norm.URL)
	}
}

func TestNormalize_MissingPortResolvesToSchemeDefault(t *testing.T) {
	norm, err := Normalize("http://example.com/api")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.Port != 80 {
		t.Errorf("Port = %d, want 80", norm.Port)
	}
}

func TestNormalize_TrailingSlashPolicy(t *testing.T) {
	withSlash, err := Normalize("https://example.com/api/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	withoutSlash, err := Normalize("https://example.com/api")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if withSlash.URL != withoutSlash.URL {
		t.Errorf("trailing slash produced a different identity: %q vs %q", withSlash.URL, withoutSlash.URL)
	}
}

func TestNormalize_RootPathKeepsSingleSlash(t *testing.T) {
	norm, err := Normalize("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.Path != "/" {
		t.Errorf("Path = %q, want \"/\"", norm.Path)
	}
}

func TestNormalize_FragmentDiscarded(t *testing.T) {
	norm, err := Normalize("https://example.com/api#section")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.URL != "https://example.com/api" {
		t.Errorf("URL = %q, fragment should be discarded", norm.URL)
	}
}

func TestNormalize_QueryPatternKeepsNamesOnlySortedAndDeduplicated(t *testing.T) {
	norm, err := Normalize("https://example.com/search?z=1&a=secret-value&a=other&m=2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.QueryPattern != "a,m,z" {
		t.Errorf("QueryPattern = %q, want \"a,m,z\"", norm.QueryPattern)
	}
	if norm.URL != "https://example.com/search" {
		t.Errorf("URL = %q, query string must not appear in the canonical URL", norm.URL)
	}
}

func TestNormalize_QueryValuesNeverRetained(t *testing.T) {
	norm, err := Normalize("https://example.com/?token=super-secret-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.QueryPattern != "token" {
		t.Errorf("QueryPattern = %q, want just the key name", norm.QueryPattern)
	}
	if strings.Contains(norm.URL, "super-secret-value") || strings.Contains(norm.QueryPattern, "super-secret-value") {
		t.Fatalf("secret query value leaked into normalized output: url=%q pattern=%q", norm.URL, norm.QueryPattern)
	}
}

func TestNormalize_PathCleaning(t *testing.T) {
	norm, err := Normalize("https://example.com//api/../api/./v1//resource")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm.Path != "/api/v1/resource" {
		t.Errorf("Path = %q, want \"/api/v1/resource\"", norm.Path)
	}
}

func TestNormalize_RejectsMissingScheme(t *testing.T) {
	if _, err := Normalize("example.com/api"); err == nil {
		t.Fatal("expected an error for a URL with no scheme")
	}
}

func TestNormalize_RejectsMissingHost(t *testing.T) {
	if _, err := Normalize("https:///api"); err == nil {
		t.Fatal("expected an error for a URL with no host")
	}
}

func TestNormalize_Deterministic(t *testing.T) {
	const raw = "HTTPS://Example.com:443/API/Path/?b=2&a=1#frag"
	first, err := Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first != second {
		t.Fatalf("Normalize is not deterministic: %+v vs %+v", first, second)
	}
}
