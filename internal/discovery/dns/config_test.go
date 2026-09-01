package dns

import (
	"testing"

	"ai-recon-platform/internal/config"
)

func testAppConfig() config.DNSDiscoveryConfig {
	return config.DNSDiscoveryConfig{
		RecordTypes: []string{"A", "AAAA"},
		Subdomains: config.DNSSubdomainConfig{
			Words:    []string{"api", "www"},
			MaxDepth: 1,
		},
		Profiles: map[string]config.DNSProfileConfig{
			"quick": {
				RecordTypes:    []string{"A"},
				SubdomainWords: []string{"api"},
				MaxDepth:       1,
			},
			"comprehensive": {
				RecordTypes:    []string{"A", "AAAA", "TXT"},
				SubdomainWords: []string{"api", "dev", "staging"},
				MaxDepth:       2, // explicit override — must win over base MaxDepth
			},
			"inherits-base-depth": {
				RecordTypes:    []string{"A"},
				SubdomainWords: []string{"api"},
				MaxDepth:       0, // 0 = inherit base
			},
		},
	}
}

func TestResolveProfile_NoProfile(t *testing.T) {
	cfg := FromAppConfig(testAppConfig())
	types, words, depth, err := cfg.ResolveProfile("")
	if err != nil {
		t.Fatalf("ResolveProfile(\"\"): %v", err)
	}
	if len(types) != 2 || types[0] != TypeA || types[1] != TypeAAAA {
		t.Errorf("types = %v, want base [A AAAA]", types)
	}
	if len(words) != 2 {
		t.Errorf("words = %v, want base [api www]", words)
	}
	if depth != 1 {
		t.Errorf("depth = %d, want base 1", depth)
	}
}

func TestResolveProfile_UnknownProfile(t *testing.T) {
	cfg := FromAppConfig(testAppConfig())
	if _, _, _, err := cfg.ResolveProfile("does-not-exist"); err == nil {
		t.Errorf("ResolveProfile(unknown) = nil error, want error")
	}
}

func TestResolveProfile_ExplicitMaxDepthWins(t *testing.T) {
	cfg := FromAppConfig(testAppConfig())
	_, _, depth, err := cfg.ResolveProfile("comprehensive")
	if err != nil {
		t.Fatalf("ResolveProfile(comprehensive): %v", err)
	}
	if depth != 2 {
		t.Errorf("depth = %d, want profile's explicit 2 (must win over base 1)", depth)
	}
}

func TestResolveProfile_ZeroMaxDepthInheritsBase(t *testing.T) {
	cfg := FromAppConfig(testAppConfig())
	_, _, depth, err := cfg.ResolveProfile("inherits-base-depth")
	if err != nil {
		t.Fatalf("ResolveProfile(inherits-base-depth): %v", err)
	}
	if depth != 1 {
		t.Errorf("depth = %d, want base 1 (profile's MaxDepth=0 must inherit, not force depth to 0)", depth)
	}
}

func TestResolveProfile_QuickProfileNarrowsWords(t *testing.T) {
	cfg := FromAppConfig(testAppConfig())
	_, words, _, err := cfg.ResolveProfile("quick")
	if err != nil {
		t.Fatalf("ResolveProfile(quick): %v", err)
	}
	if len(words) != 1 || words[0] != "api" {
		t.Errorf("words = %v, want [api] (quick profile's own word list, not base)", words)
	}
}

func TestFromAppConfig_RecordTypesConverted(t *testing.T) {
	cfg := FromAppConfig(testAppConfig())
	if len(cfg.RecordTypes) != 2 || cfg.RecordTypes[0] != TypeA {
		t.Errorf("RecordTypes = %v, want [A AAAA]", cfg.RecordTypes)
	}
}
