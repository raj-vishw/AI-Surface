package network

import (
	"reflect"
	"testing"

	domaintarget "ai-recon-platform/internal/domain/target"
)

func TestExpandTarget_Host(t *testing.T) {
	got, err := ExpandTarget(domaintarget.TypeHost, "example.local", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"example.local"}) {
		t.Errorf("got %v, want [example.local]", got)
	}
}

func TestExpandTarget_IP(t *testing.T) {
	got, err := ExpandTarget(domaintarget.TypeIP, "127.0.0.1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Errorf("got %v, want [127.0.0.1]", got)
	}
}

func TestExpandTarget_CIDR(t *testing.T) {
	got, err := ExpandTarget(domaintarget.TypeCIDR, "192.168.1.0/30", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (network/broadcast excluded)", got, want)
	}
}

func TestExpandTarget_CIDRSlash31IncludesBothAddresses(t *testing.T) {
	// RFC 3021 point-to-point exception: no network/broadcast to exclude.
	got, err := ExpandTarget(domaintarget.TypeCIDR, "10.0.0.0/31", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.0.0.0", "10.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestExpandTarget_CIDRSlash32IsSingleHost(t *testing.T) {
	got, err := ExpandTarget(domaintarget.TypeCIDR, "10.0.0.5/32", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"10.0.0.5"}) {
		t.Errorf("got %v, want [10.0.0.5]", got)
	}
}

func TestExpandTarget_HostLimitExceeded(t *testing.T) {
	_, err := ExpandTarget(domaintarget.TypeCIDR, "192.168.0.0/16", 256)
	if err == nil {
		t.Fatal("expected an error: /16 (65534 usable hosts) exceeds a 256 host limit")
	}
}

func TestExpandTarget_HostLimitRespected(t *testing.T) {
	// /24 has 254 usable hosts — must succeed under a 256 limit and fail
	// under a 100 limit.
	if _, err := ExpandTarget(domaintarget.TypeCIDR, "10.0.0.0/24", 256); err != nil {
		t.Errorf("unexpected error under a sufficient limit: %v", err)
	}
	if _, err := ExpandTarget(domaintarget.TypeCIDR, "10.0.0.0/24", 100); err == nil {
		t.Error("expected an error: 254 hosts exceeds a 100 host limit")
	}
}

func TestExpandTarget_InvalidCIDR(t *testing.T) {
	if _, err := ExpandTarget(domaintarget.TypeCIDR, "not-a-cidr", 256); err == nil {
		t.Fatal("expected an error for a malformed CIDR")
	}
}

func TestExpandTarget_UnsupportedType(t *testing.T) {
	if _, err := ExpandTarget(domaintarget.TypeDomain, "example.test", 10); err == nil {
		t.Fatal("expected an error — DOMAIN is not supported by network discovery (phase4.md §10)")
	}
	if _, err := ExpandTarget(domaintarget.TypeURL, "http://example.test", 10); err == nil {
		t.Fatal("expected an error — URL is not supported by network discovery")
	}
}

func TestSupportedTargetType(t *testing.T) {
	for _, typ := range []domaintarget.Type{domaintarget.TypeHost, domaintarget.TypeIP, domaintarget.TypeCIDR} {
		if !SupportedTargetType(typ) {
			t.Errorf("expected %s to be supported", typ)
		}
	}
	for _, typ := range []domaintarget.Type{domaintarget.TypeDomain, domaintarget.TypeURL, domaintarget.TypeRepository} {
		if SupportedTargetType(typ) {
			t.Errorf("expected %s to be unsupported", typ)
		}
	}
}
