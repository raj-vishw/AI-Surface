package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withEnv sets the given environment variables for the duration of the
// test and restores the previous values afterwards.
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		old, existed := os.LookupEnv(k)
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("setenv %s: %v", k, err)
		}
		t.Cleanup(func() {
			var restoreErr error
			if existed {
				restoreErr = os.Setenv(k, old)
			} else {
				restoreErr = os.Unsetenv(k)
			}
			if restoreErr != nil {
				t.Errorf("restoring env var %s: %v", k, restoreErr)
			}
		})
	}
}

func TestLoadDefaultsWithNoFilesOrEnv(t *testing.T) {
	dir := t.TempDir() // empty: no defaults/ or development/ subdirs
	withEnv(t, map[string]string{
		EnvVarConfigDir: dir,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Application.Environment != defaultEnvironment {
		t.Errorf("expected default environment %q, got %q", defaultEnvironment, cfg.Application.Environment)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected default logging format json, got %q", cfg.Logging.Format)
	}
	if cfg.Redis.Address != "localhost:6379" {
		t.Errorf("expected default redis address localhost:6379, got %q", cfg.Redis.Address)
	}
}

func TestLoadMergesYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "defaults", "config.yaml"), `
server:
  port: 9000
logging:
  level: warn
`)
	mustWriteFile(t, filepath.Join(dir, "development", "config.yaml"), `
server:
  host: 127.0.0.1
database:
  name: airecon_dev
`)

	withEnv(t, map[string]string{
		EnvVarConfigDir: dir,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Server.Port != 9000 {
		t.Errorf("expected port from defaults/config.yaml (9000), got %d", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("expected host from development/config.yaml, got %q", cfg.Server.Host)
	}
	if cfg.Database.Name != "airecon_dev" {
		t.Errorf("expected database name from development/config.yaml, got %q", cfg.Database.Name)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("expected logging level from defaults/config.yaml, got %q", cfg.Logging.Level)
	}
}

func TestEnvVarsOverrideYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "defaults", "config.yaml"), `
server:
  port: 9000
`)

	withEnv(t, map[string]string{
		EnvVarConfigDir: dir,
		envServerPort:   "9999",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Server.Port != 9999 {
		t.Errorf("expected env var to override YAML port, got %d", cfg.Server.Port)
	}
}

func TestLoadRejectsInvalidEnvVar(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{
		EnvVarConfigDir: dir,
		envServerPort:   "not-a-number",
	})

	if _, err := Load(); err == nil {
		t.Fatal("expected Load() to fail on an invalid AI_RECON_SERVER_PORT value")
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{
		EnvVarConfigDir: dir,
		envServerPort:   "70000", // out of range
	})

	if _, err := Load(); err == nil {
		t.Fatal("expected Load() to fail validation for an out-of-range port")
	}
}

func TestApplyOverrides(t *testing.T) {
	cfg := defaultConfig()
	host := "example.internal"
	port := 4321

	ApplyOverrides(cfg, Overrides{ServerHost: &host, ServerPort: &port})

	if cfg.Server.Host != host || cfg.Server.Port != port {
		t.Errorf("overrides not applied: got host=%q port=%d", cfg.Server.Host, cfg.Server.Port)
	}
}

func TestApplyOverridesLeavesUnsetFieldsAlone(t *testing.T) {
	cfg := defaultConfig()
	originalPort := cfg.Server.Port

	ApplyOverrides(cfg, Overrides{}) // nothing set

	if cfg.Server.Port != originalPort {
		t.Errorf("expected port to remain %d, got %d", originalPort, cfg.Server.Port)
	}
}

func TestDurationEnvVarOverride(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{
		EnvVarConfigDir:      dir,
		envServerReadTimeout: "2s",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Server.ReadTimeout != 2*time.Second {
		t.Errorf("expected read timeout 2s, got %s", cfg.Server.ReadTimeout)
	}
}

func TestRedisAddressEnvVarOverride(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{
		EnvVarConfigDir: dir,
		envRedisAddress: "redis.internal:6380",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Redis.Address != "redis.internal:6380" {
		t.Errorf("expected redis address override, got %q", cfg.Redis.Address)
	}
}

func TestSecurityEnvVarOverride(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{
		EnvVarConfigDir:                 dir,
		envSecurityRequireAuthorization: "false",
		envSecurityDryRun:               "true",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Security.RequireAuthorization {
		t.Error("expected require_authorization to be overridden to false")
	}
	if !cfg.Security.DryRun {
		t.Error("expected dry_run to be overridden to true")
	}
}

func TestLoadRejectsInvalidBooleanEnvVar(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{
		EnvVarConfigDir:   dir,
		envSecurityDryRun: "not-a-bool",
	})

	if _, err := Load(); err == nil {
		t.Fatal("expected Load() to fail on an invalid boolean env var")
	}
}

func mustWriteFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
