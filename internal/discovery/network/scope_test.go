package network

import (
	"testing"

	domaintarget "ai-recon-platform/internal/domain/target"
)

func TestScopeChecker_HostExactMatch(t *testing.T) {
	c, err := NewScopeChecker(domaintarget.TypeHost, "example.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Allowed("example.local") {
		t.Error("expected the exact host to be allowed")
	}
	if c.Allowed("other.local") {
		t.Error("expected a different host to be rejected")
	}
}

func TestScopeChecker_IPExactMatch(t *testing.T) {
	c, err := NewScopeChecker(domaintarget.TypeIP, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Allowed("127.0.0.1") {
		t.Error("expected the exact IP to be allowed")
	}
	if c.Allowed("127.0.0.2") {
		t.Error("expected a different IP to be rejected — HOST/IP scope has no subdomain-style expansion")
	}
}

func TestScopeChecker_CIDRMembership(t *testing.T) {
	c, err := NewScopeChecker(domaintarget.TypeCIDR, "192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, host := range []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"} {
		if !c.Allowed(host) {
			t.Errorf("expected %s (within 192.168.1.0/30) to be allowed", host)
		}
	}
	if c.Allowed("192.168.1.4") {
		t.Error("expected 192.168.1.4 (outside the /30) to be rejected")
	}
	if c.Allowed("10.0.0.1") {
		t.Error("expected an unrelated address to be rejected")
	}
}

func TestScopeChecker_InvalidHostString(t *testing.T) {
	c, err := NewScopeChecker(domaintarget.TypeCIDR, "192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Allowed("not-an-ip") {
		t.Error("a non-IP string must never be allowed against a CIDR scope")
	}
}

func TestScopeChecker_NilRejectsEverything(t *testing.T) {
	var c *ScopeChecker
	if c.Allowed("127.0.0.1") {
		t.Error("a nil ScopeChecker must reject everything, not panic or allow")
	}
}

func TestNewScopeChecker_UnsupportedType(t *testing.T) {
	if _, err := NewScopeChecker(domaintarget.TypeDomain, "example.test"); err == nil {
		t.Fatal("expected an error for an unsupported target type")
	}
}

func TestNewScopeChecker_InvalidCIDR(t *testing.T) {
	if _, err := NewScopeChecker(domaintarget.TypeCIDR, "not-a-cidr"); err == nil {
		t.Fatal("expected an error for a malformed CIDR")
	}
}
