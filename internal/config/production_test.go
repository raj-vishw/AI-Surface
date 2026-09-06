package config

import "testing"

// baseValidProductionConfig mirrors what configs/production/config.yaml
// actually overlays onto defaultConfig(), so this test exercises the same
// shape a real production deployment would validate at startup.
func baseValidProductionConfig() *Config {
	cfg := defaultConfig()
	cfg.Application.Environment = "production"
	cfg.Database.SSLMode = "require"
	cfg.Logging.Level = "info"
	cfg.Security.RequireAuthorization = true
	return cfg
}

func TestProductionConfig_ShippedOverlayIsValid(t *testing.T) {
	cfg := baseValidProductionConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected the production overlay shape to be valid, got %v", err)
	}
}

func TestProductionConfig_RejectsDebugLogging(t *testing.T) {
	cfg := baseValidProductionConfig()
	cfg.Logging.Level = "debug"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: debug logging must not be accepted in production")
	}
}

func TestProductionConfig_RejectsAuthorizationDisabled(t *testing.T) {
	cfg := baseValidProductionConfig()
	cfg.Security.RequireAuthorization = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: security.require_authorization=false must not be accepted in production")
	}
}

func TestProductionConfig_RejectsDisabledSSLMode(t *testing.T) {
	cfg := baseValidProductionConfig()
	cfg.Database.SSLMode = "disable"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: database.ssl_mode=disable must not be accepted in production")
	}
}

func TestProductionConfig_GuardRailsDoNotApplyOutsideProduction(t *testing.T) {
	cfg := defaultConfig() // environment stays "development"
	cfg.Logging.Level = "debug"
	cfg.Database.SSLMode = "disable"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("development config with debug logging/disabled SSL should remain valid, got %v", err)
	}
}
