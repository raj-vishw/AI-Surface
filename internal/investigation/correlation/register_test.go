package correlation

import (
	"testing"

	"ai-recon-platform/internal/investigation"
)

func TestRegisterAll_RegistersEveryRule(t *testing.T) {
	r := investigation.NewRegistry()
	if err := RegisterAll(r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"same_asset_findings", "same_endpoint_findings", "temporal_proximity",
		"technology_correlation", "same_service", "endpoint_change_with_finding",
		"authentication_colocation", "new_asset_with_finding",
	}
	for _, id := range want {
		if _, ok := r.Get(id); !ok {
			t.Errorf("expected rule %q to be registered", id)
		}
	}
	if len(r.All()) != len(want) {
		t.Errorf("expected exactly %d registered rules, got %d", len(want), len(r.All()))
	}
}
