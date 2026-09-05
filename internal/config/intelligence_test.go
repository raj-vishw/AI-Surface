package config

import "testing"

func baseValidConfigForIntelligenceTests() *Config {
	cfg := defaultConfig()
	return cfg
}

func TestIntelligenceConfig_ValidDefaults(t *testing.T) {
	cfg := baseValidConfigForIntelligenceTests()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to be valid, got %v", err)
	}
}

func TestIntelligenceConfig_NegativeProviderTimeoutInvalid(t *testing.T) {
	cfg := baseValidConfigForIntelligenceTests()
	cfg.Intelligence.ProviderTimeout = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative intelligence.provider_timeout")
	}
}

func TestIntelligenceConfig_ThreatFeedRequiresAPIKeyEnvWhenExternalEnabled(t *testing.T) {
	cfg := baseValidConfigForIntelligenceTests()
	cfg.Intelligence.External.Enabled = true
	cfg.Intelligence.ThreatFeed.BaseURL = "https://example.internal/lookup"
	cfg.Intelligence.ThreatFeed.APIKeyEnv = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when threat_feed.base_url is set without api_key_env")
	}

	cfg.Intelligence.ThreatFeed.APIKeyEnv = "MY_FEED_API_KEY"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config once api_key_env is set, got %v", err)
	}
}

func TestIntelligenceConfig_NegativeRequestsPerSecondInvalid(t *testing.T) {
	cfg := baseValidConfigForIntelligenceTests()
	cfg.Intelligence.ThreatFeed.RequestsPerSecond = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative threat_feed.requests_per_second")
	}
}

func TestIntelligenceConfig_DisabledSkipsValidation(t *testing.T) {
	cfg := baseValidConfigForIntelligenceTests()
	cfg.Intelligence.Enabled = false
	cfg.Intelligence.ProviderTimeout = -1 // would be invalid if intelligence were enabled
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected disabled intelligence config to skip its own validation, got %v", err)
	}
}
