package endpoint

import "testing"

func TestTemplatePath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/users/123", "/users/{id}"},
		{"/users/456", "/users/{id}"},
		{"/users/admin", "/users/admin"},
		{"/users/settings", "/users/settings"},
		{"/users/550e8400-e29b-41d4-a716-446655440000", "/users/{id}"},
		{"/api/v1/orders/42/items/7", "/api/v1/orders/{id}/items/{id}"},
		{"/", "/"},
		{"/dashboard", "/dashboard"},
		{"/administration", "/administration"}, // long, all-alphabetic — must not be templated
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := TemplatePath(tc.path); got != tc.want {
				t.Errorf("TemplatePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestTemplatePath_LongOpaqueTokenWithDigit(t *testing.T) {
	got := TemplatePath("/sessions/a1b2c3d4e5f6g7h8i9j0")
	want := "/sessions/{id}"
	if got != want {
		t.Errorf("TemplatePath(long opaque token) = %q, want %q", got, want)
	}
}

func TestTemplatePath_ShortWordNeverTemplated(t *testing.T) {
	got := TemplatePath("/api/health")
	if got != "/api/health" {
		t.Errorf("TemplatePath(/api/health) = %q, want unchanged", got)
	}
}
