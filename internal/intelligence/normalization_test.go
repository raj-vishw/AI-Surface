package intelligence

import "testing"

func TestNormalize_Domain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"EXAMPLE.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com.", "example.com"},
		{"Sub.EXAMPLE.com", "sub.example.com"},
	}
	for _, c := range cases {
		got := Normalize(Indicator{Type: IndicatorDomain, Value: c.in})
		if got.Value != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got.Value, c.want)
		}
	}
}

func TestNormalize_IP(t *testing.T) {
	v4 := Normalize(Indicator{Type: IndicatorIPv4, Value: "  192.168.1.1  "})
	if v4.Value != "192.168.1.1" {
		t.Errorf("ipv4 = %q, want 192.168.1.1", v4.Value)
	}
	v6 := Normalize(Indicator{Type: IndicatorIPv6, Value: "2001:0db8:0000:0000:0000:0000:0000:0001"})
	if v6.Value != "2001:db8::1" {
		t.Errorf("ipv6 = %q, want 2001:db8::1", v6.Value)
	}
	// Idempotent
	twice := Normalize(v4)
	if twice.Value != v4.Value {
		t.Errorf("normalize not idempotent: %q != %q", twice.Value, v4.Value)
	}
}

func TestNormalize_URL_PreservesPathAndQuery(t *testing.T) {
	got := Normalize(Indicator{Type: IndicatorURL, Value: "HTTPS://Example.COM:443/Path?token=abc&Name=X"})
	want := "https://example.com/Path?token=abc&Name=X"
	if got.Value != want {
		t.Errorf("Normalize URL = %q, want %q", got.Value, want)
	}
}

func TestNormalize_URL_NonDefaultPortPreserved(t *testing.T) {
	got := Normalize(Indicator{Type: IndicatorURL, Value: "https://example.com:8443/x"})
	want := "https://example.com:8443/x"
	if got.Value != want {
		t.Errorf("Normalize URL = %q, want %q", got.Value, want)
	}
}

func TestNormalize_Hash(t *testing.T) {
	got := Normalize(Indicator{Type: IndicatorHash, Value: "  ABCDEF0123  "})
	if got.Value != "abcdef0123" {
		t.Errorf("Normalize hash = %q, want abcdef0123", got.Value)
	}
}
