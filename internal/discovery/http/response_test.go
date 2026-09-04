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

func TestExtractCookieAttributes_CapturesAttributesNotValues(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "session=super-secret-value-123; Secure; HttpOnly; SameSite=Strict")
	h.Add("Set-Cookie", "tracking=abc; SameSite=None")
	h.Add("Set-Cookie", "insecure=xyz")

	cookies := extractCookieAttributes(h)
	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies, got %d: %#v", len(cookies), cookies)
	}

	if cookies[0].Name != "session" || !cookies[0].Secure || !cookies[0].HTTPOnly || cookies[0].SameSite != "Strict" {
		t.Errorf("session cookie attributes wrong: %#v", cookies[0])
	}
	if cookies[1].Name != "tracking" || cookies[1].Secure || cookies[1].HTTPOnly || cookies[1].SameSite != "None" {
		t.Errorf("tracking cookie attributes wrong: %#v", cookies[1])
	}
	if cookies[2].Name != "insecure" || cookies[2].Secure || cookies[2].HTTPOnly || cookies[2].SameSite != "" {
		t.Errorf("insecure cookie attributes wrong: %#v", cookies[2])
	}
}

func TestExtractCookieAttributes_NoCookies(t *testing.T) {
	if cookies := extractCookieAttributes(http.Header{}); cookies != nil {
		t.Errorf("extractCookieAttributes(empty) = %v, want nil", cookies)
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
