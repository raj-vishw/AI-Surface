package asset

import (
	"testing"

	"github.com/google/uuid"
)

func strPtr(s string) *string { return &s }
func intPtr(n int) *int       { return &n }

func validHostAsset() Asset {
	return Asset{
		TargetID: uuid.New(),
		Type:     TypeHost,
		Hostname: strPtr("api.example.com"),
		Source:   "dns",
		Status:   StatusDiscovered,
	}
}

func TestValidate_ValidAsset(t *testing.T) {
	if err := validHostAsset().Validate(); err != nil {
		t.Fatalf("expected valid asset, got error: %v", err)
	}
}

func TestValidate_MissingTargetID(t *testing.T) {
	a := validHostAsset()
	a.TargetID = uuid.Nil
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for missing target_id")
	}
}

func TestValidate_UnrecognizedType(t *testing.T) {
	a := validHostAsset()
	a.Type = "NOT_A_TYPE"
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for unrecognized type")
	}
}

func TestValidate_EmptySource(t *testing.T) {
	a := validHostAsset()
	a.Source = ""
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for empty source")
	}
}

func TestValidate_OutOfRangeConfidence(t *testing.T) {
	for _, c := range []Confidence{-0.1, 1.1} {
		a := validHostAsset()
		a.Confidence = c
		if err := a.Validate(); err == nil {
			t.Errorf("expected error for confidence %v", c)
		}
	}
}

func TestValidate_OutOfRangePort(t *testing.T) {
	a := validHostAsset()
	a.Type = TypePort
	a.Port = intPtr(70000)
	if err := a.Validate(); err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestConfidence_Level(t *testing.T) {
	cases := []struct {
		c        Confidence
		expected Level
	}{
		{0.0, LevelUnknown},
		{0.1, LevelUnknown},
		{0.25, LevelLow},
		{0.4, LevelLow},
		{0.5, LevelMedium},
		{0.6, LevelMedium},
		{0.75, LevelHigh},
		{0.9, LevelHigh},
		{1.0, LevelConfirmed},
	}
	for _, tc := range cases {
		if got := tc.c.Level(); got != tc.expected {
			t.Errorf("Confidence(%v).Level() = %v, want %v", tc.c, got, tc.expected)
		}
	}
}

func TestIdentity_HostAssetIsHostnameNormalized(t *testing.T) {
	targetID := uuid.New()
	a1 := Asset{TargetID: targetID, Type: TypeHost, Hostname: strPtr("API.Example.com.")}
	a2 := Asset{TargetID: targetID, Type: TypeHost, Hostname: strPtr("api.example.com")}

	id1, err := Identity(a1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id2, err := Identity(a2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1 != id2 {
		t.Errorf("expected equivalent hostnames to produce the same identity: %q vs %q", id1, id2)
	}
}

func TestIdentity_IPAssetRequiresValidIP(t *testing.T) {
	a := Asset{TargetID: uuid.New(), Type: TypeIP, IP: strPtr("not-an-ip")}
	if _, err := Identity(a); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestIdentity_PortAssetCombinesHostPortProtocol(t *testing.T) {
	targetID := uuid.New()
	a := Asset{
		TargetID: targetID, Type: TypePort,
		Hostname: strPtr("api.example.com"), Port: intPtr(443), Protocol: strPtr("TCP"),
	}
	id, err := Identity(a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	other := Asset{
		TargetID: targetID, Type: TypePort,
		Hostname: strPtr("api.example.com"), Port: intPtr(8443), Protocol: strPtr("tcp"),
	}
	otherID, err := Identity(other)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == otherID {
		t.Errorf("different ports must not collide: %q == %q", id, otherID)
	}
}

func TestIdentity_EndpointAssetUsesNormalizedURL(t *testing.T) {
	targetID := uuid.New()
	a1 := Asset{TargetID: targetID, Type: TypeHTTPEndpoint, URL: strPtr("https://EXAMPLE.com:443/api/")}
	a2 := Asset{TargetID: targetID, Type: TypeHTTPEndpoint, URL: strPtr("https://example.com/api")}

	id1, err := Identity(a1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id2, err := Identity(a2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1 != id2 {
		t.Errorf("expected equivalent URLs to produce the same identity: %q vs %q", id1, id2)
	}
}

// TestIdentity_DuplicateDiscoverySources reproduces phase2.md §19's example:
// the same logical asset discovered via DNS, HTTP, and TLS should collapse
// to a single identity when it's the same asset type/value.
func TestIdentity_DuplicateDiscoverySources(t *testing.T) {
	targetID := uuid.New()
	dns := Asset{TargetID: targetID, Type: TypeSubdomain, Hostname: strPtr("api.example.com"), Source: "dns"}
	tls := Asset{TargetID: targetID, Type: TypeSubdomain, Hostname: strPtr("api.example.com"), Source: "certificate_transparency"}

	dnsID, err := IdentityKey(dns)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tlsID, err := IdentityKey(tls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dnsID != tlsID {
		t.Errorf("same hostname discovered by different sources must share an identity key: %q vs %q", dnsID, tlsID)
	}
}

func TestIdentity_DifferentAssetsNeverCollide(t *testing.T) {
	targetID := uuid.New()
	host := Asset{TargetID: targetID, Type: TypeHost, Hostname: strPtr("api.example.com")}
	endpoint := Asset{TargetID: targetID, Type: TypeHTTPEndpoint, URL: strPtr("https://api.example.com/")}

	hostKey, err := IdentityKey(host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	endpointKey, err := IdentityKey(endpoint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hostKey == endpointKey {
		t.Error("a HOST asset and an HTTP_ENDPOINT asset for the same hostname must not collide")
	}
}

func TestIdentityKey_IsSHA256Hex(t *testing.T) {
	key, err := IdentityKey(validHostAsset())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("IdentityKey length = %d, want 64 (sha256 hex)", len(key))
	}
}

func TestIdentity_Deterministic(t *testing.T) {
	a := validHostAsset()
	first, err := Identity(a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := Identity(a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first != second {
		t.Fatalf("Identity is not deterministic: %q vs %q", first, second)
	}
}
