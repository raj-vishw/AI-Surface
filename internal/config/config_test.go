package config

import "testing"

func TestValidateAcceptsDefaultConfig(t *testing.T) {
	cfg := defaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid, got error: %v", err)
	}
}

func TestValidateRejectsInvalidPort(t *testing.T) {
	cfg := defaultConfig()
	cfg.Server.Port = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for port 0")
	}

	cfg.Server.Port = 70000
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for port 70000")
	}
}

func TestValidateRejectsMissingDatabaseFields(t *testing.T) {
	cfg := defaultConfig()
	cfg.Database.Host = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty database host")
	}
}

func TestValidateRejectsUnknownSSLMode(t *testing.T) {
	cfg := defaultConfig()
	cfg.Database.SSLMode = "yolo"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for unknown ssl mode")
	}
}

func TestValidateRejectsUnknownLogLevel(t *testing.T) {
	cfg := defaultConfig()
	cfg.Logging.Level = "verbose"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for unknown log level")
	}
}

func TestValidateRejectsUnknownEnvironment(t *testing.T) {
	cfg := defaultConfig()
	cfg.Application.Environment = "prod-ish"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for unrecognized environment")
	}
}

func TestValidateRejectsIdleExceedingOpenConnections(t *testing.T) {
	cfg := defaultConfig()
	cfg.Database.MaxOpenConnections = 5
	cfg.Database.MaxIdleConnections = 10
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when max_idle_connections exceeds max_open_connections")
	}
}

func TestValidateRejectsInvalidRedisAddress(t *testing.T) {
	cfg := defaultConfig()
	cfg.Redis.Address = "not-a-host-port"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for redis address without a port")
	}
}

func TestValidateRejectsInvalidHTTPClientLimits(t *testing.T) {
	cfg := defaultConfig()
	cfg.HTTPClient.MaxResponseSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero max_response_size")
	}
}

func TestValidateAggregatesMultipleErrors(t *testing.T) {
	cfg := defaultConfig()
	cfg.Server.Port = 0
	cfg.Database.Host = ""
	cfg.Logging.Level = "bogus"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDatabaseDSNAndRedactedDSN(t *testing.T) {
	cfg := defaultConfig()
	cfg.Database.Password = "supersecret"

	dsn := cfg.Database.DSN()
	if dsn == "" {
		t.Fatal("DSN() must not be empty")
	}

	redacted := cfg.Database.RedactedDSN()
	if redacted == dsn {
		t.Fatal("RedactedDSN() must differ from DSN() when a password is set")
	}
	if contains := (func(s, substr string) bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})(redacted, "supersecret"); contains {
		t.Fatal("RedactedDSN() must not contain the raw password")
	}
}

func TestServerAddr(t *testing.T) {
	cfg := defaultConfig()
	if got := cfg.Server.Addr(); got != "0.0.0.0:8080" {
		t.Errorf("unexpected server addr: %q", got)
	}
}
