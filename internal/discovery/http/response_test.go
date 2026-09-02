package http

import (
	"net/http"
	"testing"
)

func TestExtractCookieNames(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "JSESSIONID=ABC123; Path=/; HttpOnly")
	h.Add("Set-Cookie", "csrftoken=xyz789; Secure")

	names := extractCookieNames(h)
	if len(names) != 2 || names[0] != "JSESSIONID" || names[1] != "csrftoken" {
		t.Errorf("extractCookieNames() = %v, want [JSESSIONID csrftoken]", names)
	}
}

func TestExtractCookieNames_NeverLeaksValue(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "session=super-secret-value-123")

	names := extractCookieNames(h)
	for _, n := range names {
		if n != "session" {
			t.Errorf("extractCookieNames() leaked the value: %v", names)
		}
	}
	if len(names) != 1 {
		t.Fatalf("names = %v, want exactly [session]", names)
	}
}

func TestExtractCookieNames_Dedup(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "sid=abc; Path=/")
	h.Add("Set-Cookie", "sid=def; Path=/other") // same name, different value/attrs
	names := extractCookieNames(h)
	if len(names) != 1 || names[0] != "sid" {
		t.Errorf("extractCookieNames() = %v, want [sid] (deduplicated)", names)
	}
}

func TestExtractCookieNames_NoCookies(t *testing.T) {
	if names := extractCookieNames(http.Header{}); names != nil {
		t.Errorf("extractCookieNames(empty) = %v, want nil", names)
	}
}

func TestExtractCookieNames_MalformedIgnored(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "") // malformed
	h.Add("Set-Cookie", "valid=1")
	names := extractCookieNames(h)
	if len(names) != 1 || names[0] != "valid" {
		t.Errorf("extractCookieNames() = %v, want [valid]", names)
	}
}
