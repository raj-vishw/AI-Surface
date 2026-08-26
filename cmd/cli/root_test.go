package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestConfigValidateCommandSucceedsWithDefaults(t *testing.T) {
	dir := t.TempDir() // no config files present -> falls back to built-in defaults

	cmd := newRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"config", "validate", "--config-dir", dir, "--env", "development"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if !strings.Contains(buf.String(), "configuration is valid") {
		t.Errorf("expected success message, got %q", buf.String())
	}
}

func TestConfigValidateCommandLogLevelOverride(t *testing.T) {
	dir := t.TempDir()

	cmd := newRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"config", "validate", "--config-dir", dir, "--log-level", "debug"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if !strings.Contains(buf.String(), "log level:   debug") {
		t.Errorf("expected --log-level override to be reflected in output, got %q", buf.String())
	}
}

func TestVersionCommandIsRegistered(t *testing.T) {
	cmd := newRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "ai-recon") {
		t.Errorf("expected version output, got %q", buf.String())
	}
}

func TestHealthCommandFailsAndReturnsNonNilErrorWhenUnreachable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AI_RECON_DATABASE_HOST", "127.0.0.1")
	t.Setenv("AI_RECON_DATABASE_PORT", "1") // reserved port, nothing listening
	t.Setenv("AI_RECON_DATABASE_CONNECT_TIMEOUT", "200ms")
	t.Setenv("AI_RECON_REDIS_ADDRESS", "127.0.0.1:1")
	t.Setenv("AI_RECON_REDIS_CONNECT_TIMEOUT", "200ms")

	cmd := newRootCommand()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"health", "--config-dir", dir})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected health command to return a non-nil error when dependencies are unreachable")
	}

	if !strings.Contains(buf.String(), "unavailable") {
		t.Errorf("expected output to report unavailable dependencies, got %q", buf.String())
	}
}
