package target

import "testing"

func TestValidate_ValidTargets(t *testing.T) {
	cases := []Target{
		{Name: "example domain", Type: TypeDomain, Value: "example.com"},
		{Name: "example host", Type: TypeHost, Value: "10.0.0.5"},
		{Name: "example ip", Type: TypeIP, Value: "192.168.1.1"},
		{Name: "example cidr", Type: TypeCIDR, Value: "10.0.0.0/24"},
		{Name: "example url", Type: TypeURL, Value: "https://example.com/app"},
		{Name: "example repo url", Type: TypeRepository, Value: "https://github.com/example/repo"},
		{Name: "example repo shorthand", Type: TypeRepository, Value: "example/repo"},
		{Name: "example repo scp", Type: TypeRepository, Value: "git@github.com:example/repo.git"},
		{Name: "example cloud account", Type: TypeCloudAccount, Value: "123456789012"},
	}
	for _, tc := range cases {
		if err := tc.Validate(); err != nil {
			t.Errorf("expected %+v to be valid, got error: %v", tc, err)
		}
	}
}

func TestValidate_InvalidTargets(t *testing.T) {
	cases := []struct {
		name string
		t    Target
	}{
		{"empty name", Target{Type: TypeDomain, Value: "example.com"}},
		{"empty value", Target{Name: "x", Type: TypeDomain, Value: ""}},
		{"unrecognized type", Target{Name: "x", Type: "NOT_A_TYPE", Value: "example.com"}},
		{"malformed domain", Target{Name: "x", Type: TypeDomain, Value: "not a domain!!"}},
		{"malformed ip", Target{Name: "x", Type: TypeIP, Value: "999.999.999.999"}},
		{"malformed cidr", Target{Name: "x", Type: TypeCIDR, Value: "10.0.0.0/999"}},
		{"malformed url", Target{Name: "x", Type: TypeURL, Value: "not-a-url"}},
		{"malformed repository", Target{Name: "x", Type: TypeRepository, Value: "!!!not valid!!!"}},
		{"invalid authorization status", Target{Name: "x", Type: TypeDomain, Value: "example.com", AuthorizationStatus: "MADE_UP"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.t.Validate(); err == nil {
				t.Errorf("expected %+v to be invalid", tc.t)
			}
		})
	}
}

func TestValidate_NeverPerformsNetworkIO(t *testing.T) {
	// A hostname that would fail DNS resolution must still validate
	// successfully — Validate is a format check only.
	target := Target{Name: "x", Type: TypeDomain, Value: "definitely-does-not-resolve.invalid"}
	if err := target.Validate(); err != nil {
		t.Fatalf("Validate should not attempt DNS resolution, got error: %v", err)
	}
}

func TestIsAuthorized(t *testing.T) {
	cases := []struct {
		status   AuthorizationStatus
		expected bool
	}{
		{AuthorizationUnverified, false},
		{AuthorizationAuthorized, true},
		{AuthorizationExpired, false},
		{AuthorizationRevoked, false},
		{"", false},
	}
	for _, tc := range cases {
		target := Target{AuthorizationStatus: tc.status}
		if got := target.IsAuthorized(); got != tc.expected {
			t.Errorf("status %q: IsAuthorized() = %v, want %v", tc.status, got, tc.expected)
		}
	}
}

func TestValidate_Deterministic(t *testing.T) {
	target := Target{Name: "x", Type: TypeDomain, Value: "example.com"}
	err1 := target.Validate()
	err2 := target.Validate()
	if (err1 == nil) != (err2 == nil) {
		t.Fatalf("Validate produced different results on repeated calls: %v vs %v", err1, err2)
	}
}
