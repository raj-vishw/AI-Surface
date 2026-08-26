// Package config defines the platform's configuration schema and the
// layered loader used to build it (see loader.go).
package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved application configuration.
type Config struct {
	Application ApplicationConfig `yaml:"application"`
	Server      ServerConfig      `yaml:"server"`
	Database    DatabaseConfig    `yaml:"database"`
	Redis       RedisConfig       `yaml:"redis"`
	HTTPClient  HTTPClientConfig  `yaml:"http_client"`
	Logging     LoggingConfig     `yaml:"logging"`
	Security    SecurityConfig    `yaml:"security"`
}

// ApplicationConfig identifies the running application/environment.
type ApplicationConfig struct {
	Name        string `yaml:"name"`
	Environment string `yaml:"environment"`
	Version     string `yaml:"version"`
}

// ServerConfig configures the HTTP API server.
type ServerConfig struct {
	Host              string        `yaml:"host"`
	Port              int           `yaml:"port"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"`
}

// Addr returns the host:port the server should listen on.
func (s ServerConfig) Addr() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// DatabaseConfig configures the PostgreSQL connection and pool.
type DatabaseConfig struct {
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port"`
	User           string        `yaml:"user"`
	Password       string        `yaml:"password"`
	Name           string        `yaml:"name"`
	SSLMode        string        `yaml:"ssl_mode"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`

	MaxOpenConnections int32         `yaml:"max_open_connections"`
	MaxIdleConnections int32         `yaml:"max_idle_connections"`
	ConnMaxLifetime    time.Duration `yaml:"connection_max_lifetime"`
	ConnMaxIdleTime    time.Duration `yaml:"connection_max_idle_time"`
}

// DSN renders the connection string consumed by pgx. The password is
// included because pgx needs it to connect; callers must never log the
// resulting string.
func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode,
	)
}

// RedactedDSN renders the DSN with the password masked, safe for logging.
func (d DatabaseConfig) RedactedDSN() string {
	return fmt.Sprintf(
		"postgres://%s:***@%s:%d/%s?sslmode=%s",
		d.User, d.Host, d.Port, d.Name, d.SSLMode,
	)
}

// RedisConfig configures the Redis connection.
type RedisConfig struct {
	Address        string        `yaml:"address"`
	Password       string        `yaml:"password"`
	Database       int           `yaml:"database"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// HTTPClientConfig configures internal/httpclient's default Client. It is
// infrastructure for future discovery/fingerprinting subsystems, not the
// discovery engine itself.
type HTTPClientConfig struct {
	Timeout               time.Duration `yaml:"timeout"`
	MaxIdleConnections    int           `yaml:"max_idle_connections"`
	MaxConnectionsPerHost int           `yaml:"max_connections_per_host"`
	MaxResponseSize       int64         `yaml:"max_response_size"`
	MaxRedirects          int           `yaml:"max_redirects"`
}

// LoggingConfig configures the structured logger.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// SecurityConfig enforces the platform's authorization/safety boundary
// (see work.md §2). RequireAuthorization and DryRun are read by later
// phases' scanning subsystems; Phase 1 only carries the settings through
// configuration and validation.
type SecurityConfig struct {
	RequireAuthorization bool `yaml:"require_authorization"`
	DryRun               bool `yaml:"dry_run"`
}

var validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
var validLogFormats = map[string]bool{"json": true, "text": true}
var validSSLModes = map[string]bool{"disable": true, "require": true, "verify-ca": true, "verify-full": true, "prefer": true, "allow": true}
var validEnvironments = map[string]bool{"development": true, "staging": true, "production": true, "test": true}

// Validate checks that the configuration is internally consistent and
// usable. It is intentionally strict: an invalid configuration should fail
// fast at startup rather than surface as a confusing runtime error later.
// It never silently substitutes a default for an invalid value.
func (c *Config) Validate() error {
	var errs []string

	if strings.TrimSpace(c.Application.Name) == "" {
		errs = append(errs, "application.name must not be empty")
	}
	if !validEnvironments[strings.ToLower(c.Application.Environment)] {
		errs = append(errs, fmt.Sprintf("application.environment %q must be one of development, staging, production, test", c.Application.Environment))
	}

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Sprintf("server.port must be between 1 and 65535, got %d", c.Server.Port))
	}
	if strings.TrimSpace(c.Server.Host) == "" {
		errs = append(errs, "server.host must not be empty")
	}
	if c.Server.ReadHeaderTimeout <= 0 {
		errs = append(errs, "server.read_header_timeout must be positive")
	}
	if c.Server.ReadTimeout <= 0 {
		errs = append(errs, "server.read_timeout must be positive")
	}
	if c.Server.WriteTimeout <= 0 {
		errs = append(errs, "server.write_timeout must be positive")
	}
	if c.Server.IdleTimeout <= 0 {
		errs = append(errs, "server.idle_timeout must be positive")
	}
	if c.Server.ShutdownTimeout <= 0 {
		errs = append(errs, "server.shutdown_timeout must be positive")
	}

	if strings.TrimSpace(c.Database.Host) == "" {
		errs = append(errs, "database.host must not be empty")
	}
	if c.Database.Port < 1 || c.Database.Port > 65535 {
		errs = append(errs, fmt.Sprintf("database.port must be between 1 and 65535, got %d", c.Database.Port))
	}
	if strings.TrimSpace(c.Database.User) == "" {
		errs = append(errs, "database.user must not be empty")
	}
	if strings.TrimSpace(c.Database.Name) == "" {
		errs = append(errs, "database.name must not be empty")
	}
	if !validSSLModes[c.Database.SSLMode] {
		errs = append(errs, fmt.Sprintf("database.ssl_mode %q is not a recognized sslmode", c.Database.SSLMode))
	}
	if c.Database.MaxOpenConnections < 1 {
		errs = append(errs, "database.max_open_connections must be at least 1")
	}
	if c.Database.MaxIdleConnections < 0 {
		errs = append(errs, "database.max_idle_connections must not be negative")
	}
	if c.Database.MaxIdleConnections > c.Database.MaxOpenConnections {
		errs = append(errs, "database.max_idle_connections must not exceed database.max_open_connections")
	}
	if c.Database.ConnMaxLifetime < 0 {
		errs = append(errs, "database.connection_max_lifetime must not be negative")
	}
	if c.Database.ConnMaxIdleTime < 0 {
		errs = append(errs, "database.connection_max_idle_time must not be negative")
	}
	if c.Database.ConnectTimeout <= 0 {
		errs = append(errs, "database.connect_timeout must be positive")
	}

	if strings.TrimSpace(c.Redis.Address) == "" {
		errs = append(errs, "redis.address must not be empty")
	} else if _, _, err := net.SplitHostPort(c.Redis.Address); err != nil {
		errs = append(errs, fmt.Sprintf("redis.address %q must be a host:port pair", c.Redis.Address))
	}
	if c.Redis.Database < 0 {
		errs = append(errs, "redis.database must not be negative")
	}
	if c.Redis.ConnectTimeout <= 0 {
		errs = append(errs, "redis.connect_timeout must be positive")
	}

	if c.HTTPClient.Timeout <= 0 {
		errs = append(errs, "http_client.timeout must be positive")
	}
	if c.HTTPClient.MaxIdleConnections < 1 {
		errs = append(errs, "http_client.max_idle_connections must be at least 1")
	}
	if c.HTTPClient.MaxConnectionsPerHost < 1 {
		errs = append(errs, "http_client.max_connections_per_host must be at least 1")
	}
	if c.HTTPClient.MaxResponseSize < 1 {
		errs = append(errs, "http_client.max_response_size must be at least 1")
	}
	if c.HTTPClient.MaxRedirects < 0 {
		errs = append(errs, "http_client.max_redirects must not be negative")
	}

	if !validLogLevels[strings.ToLower(c.Logging.Level)] {
		errs = append(errs, fmt.Sprintf("logging.level %q must be one of debug, info, warn, error", c.Logging.Level))
	}
	if !validLogFormats[strings.ToLower(c.Logging.Format)] {
		errs = append(errs, fmt.Sprintf("logging.format %q must be one of json, text", c.Logging.Format))
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
