package network

import (
	"reflect"
	"testing"

	"ai-recon-platform/internal/config"
)

func TestConfig_ResolvePorts_NoProfile(t *testing.T) {
	cfg := Config{}
	got, err := cfg.ResolvePorts("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil ports with no profile, got %v", got)
	}
}

func TestConfig_ResolvePorts_KnownProfile(t *testing.T) {
	cfg := Config{Profiles: map[string]config.NetworkProfileConfig{
		"quick": {Ports: []int{80, 443}},
	}}
	got, err := cfg.ResolvePorts("quick")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []int{80, 443}) {
		t.Errorf("got %v, want [80 443]", got)
	}
}

func TestConfig_ResolvePorts_UnknownProfile(t *testing.T) {
	cfg := Config{Profiles: map[string]config.NetworkProfileConfig{
		"quick": {Ports: []int{80}},
	}}
	if _, err := cfg.ResolvePorts("nonexistent"); err == nil {
		t.Fatal("expected an error for an unknown profile")
	}
}

func TestFromAppConfig(t *testing.T) {
	appCfg := config.NetworkDiscoveryConfig{
		MaxConcurrency:     50,
		HTTPCandidatePorts: []int{80, 443},
		AICandidatePorts:   []int{11434},
	}
	got := FromAppConfig(appCfg)
	if got.MaxConcurrency != 50 {
		t.Errorf("MaxConcurrency = %d, want 50", got.MaxConcurrency)
	}
	if !reflect.DeepEqual(got.HTTPCandidatePorts, []int{80, 443}) {
		t.Errorf("HTTPCandidatePorts = %v, want [80 443]", got.HTTPCandidatePorts)
	}
}
