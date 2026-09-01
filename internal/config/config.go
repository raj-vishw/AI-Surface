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
	Discovery   DiscoveryConfig   `yaml:"discovery"`
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

// DiscoveryConfig configures the platform's discovery subsystems. Phase 3
// added HTTP; Phase 4 adds Network (TCP connect scanning). Later phases
// (DNS, ...) add further siblings here, not new top-level config sections.
type DiscoveryConfig struct {
	HTTP    HTTPDiscoveryConfig    `yaml:"http"`
	Network NetworkDiscoveryConfig `yaml:"network"`
}

// ProfileConfig names one reusable set of paths a scan can be run with
// (e.g. "quick" vs "comprehensive" — see internal/discovery/http). Kept
// data-only and configurable rather than hard-coded so an operator can add
// or edit profiles without recompiling.
type ProfileConfig struct {
	Paths []string `yaml:"paths"`
}

// NetworkProfileConfig names one reusable set of ports a network scan can
// be run with (e.g. "quick"/"standard"/"comprehensive" — see
// internal/discovery/network). Data-only, same rationale as ProfileConfig.
type NetworkProfileConfig struct {
	Ports []int `yaml:"ports"`
}

// NetworkDiscoveryConfig configures the TCP connect discovery engine
// (internal/discovery/network). It does not configure a second HTTP
// transport or a second database layer — port discovery is TCP-connect
// only; HTTP/AI candidates it flags are for a later HTTP discovery pass
// (Phase 3's engine, run separately) to investigate.
type NetworkDiscoveryConfig struct {
	Enabled bool `yaml:"enabled"`
	// ConnectTimeout bounds every individual TCP connection attempt —
	// never unlimited (phase4.md §15).
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	// MaxHosts bounds how many addresses a CIDR target may expand to —
	// exceeding it is a configuration/validation error, not a truncation
	// (phase4.md §11).
	MaxHosts int `yaml:"max_hosts"`
	// RequestsPerSecond paces connection attempts; 0 means unlimited. This
	// is a safety/stability control, not stealth/evasion timing
	// (phase4.md §18/§50).
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	// HTTPCandidatePorts are ports whose OPEN state additionally sets
	// HTTPCandidate=true on the result/asset — "worth a Phase 3 HTTP scan
	// later", never a confirmed HTTP service.
	HTTPCandidatePorts []int `yaml:"http_candidate_ports"`
	// AICandidatePorts are ports whose OPEN state additionally sets
	// AIServiceCandidate=true — "worth further investigation", never a
	// confirmed AI service (phase4.md §24).
	AICandidatePorts []int                           `yaml:"ai_candidate_ports"`
	Profiles         map[string]NetworkProfileConfig `yaml:"profiles"`
}

// HTTPDiscoveryConfig configures the HTTP discovery engine
// (internal/discovery/http). It reuses HTTPClientConfig's underlying
// transport (internal/httpclient) — this section only adds discovery-
// specific policy: which paths/methods/schemes to try, concurrency, and AI
// candidate detection.
type HTTPDiscoveryConfig struct {
	Enabled           bool                     `yaml:"enabled"`
	Timeout           time.Duration            `yaml:"timeout"`
	MaxConcurrency    int                      `yaml:"max_concurrency"`
	MaxResponseSize   int64                    `yaml:"max_response_size"`
	FollowRedirects   bool                     `yaml:"follow_redirects"`
	MaxRedirects      int                      `yaml:"max_redirects"`
	Methods           []string                 `yaml:"methods"`
	Schemes           []string                 `yaml:"schemes"`
	Paths             []string                 `yaml:"paths"`
	DetectAIEndpoints bool                     `yaml:"detect_ai_endpoints"`
	Profiles          map[string]ProfileConfig `yaml:"profiles"`
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

	if c.Discovery.HTTP.Enabled {
		h := c.Discovery.HTTP
		if h.Timeout <= 0 {
			errs = append(errs, "discovery.http.timeout must be positive")
		}
		if h.MaxConcurrency < 1 {
			errs = append(errs, "discovery.http.max_concurrency must be at least 1")
		}
		if h.MaxResponseSize < 1 {
			errs = append(errs, "discovery.http.max_response_size must be at least 1")
		}
		if h.MaxRedirects < 0 {
			errs = append(errs, "discovery.http.max_redirects must not be negative")
		}
		if len(h.Methods) == 0 {
			errs = append(errs, "discovery.http.methods must not be empty")
		}
		for _, m := range h.Methods {
			// Phase 3 is discovery only: GET-only is a required safe
			// default (master spec phase3.md §6), not merely a suggestion.
			if m != "GET" {
				errs = append(errs, fmt.Sprintf("discovery.http.methods: %q is not permitted — HTTP discovery is GET-only", m))
			}
		}
		if len(h.Schemes) == 0 {
			errs = append(errs, "discovery.http.schemes must not be empty")
		}
		for _, s := range h.Schemes {
			if s != "http" && s != "https" {
				errs = append(errs, fmt.Sprintf("discovery.http.schemes: %q must be \"http\" or \"https\"", s))
			}
		}
		if len(h.Paths) == 0 {
			errs = append(errs, "discovery.http.paths must not be empty")
		}
		for _, p := range h.Paths {
			if !strings.HasPrefix(p, "/") {
				errs = append(errs, fmt.Sprintf("discovery.http.paths: %q must start with \"/\"", p))
			}
		}
		for name, profile := range h.Profiles {
			if len(profile.Paths) == 0 {
				errs = append(errs, fmt.Sprintf("discovery.http.profiles.%s.paths must not be empty", name))
			}
			for _, p := range profile.Paths {
				if !strings.HasPrefix(p, "/") {
					errs = append(errs, fmt.Sprintf("discovery.http.profiles.%s.paths: %q must start with \"/\"", name, p))
				}
			}
		}
	}

	if c.Discovery.Network.Enabled {
		n := c.Discovery.Network
		if n.ConnectTimeout <= 0 {
			errs = append(errs, "discovery.network.connect_timeout must be positive")
		}
		if n.MaxConcurrency < 1 {
			errs = append(errs, "discovery.network.max_concurrency must be at least 1")
		}
		if n.MaxHosts < 1 {
			errs = append(errs, "discovery.network.max_hosts must be at least 1")
		}
		if n.RequestsPerSecond < 0 {
			errs = append(errs, "discovery.network.requests_per_second must not be negative")
		}
		validatePortList := func(field string, ports []int) {
			for _, p := range ports {
				if p < 1 || p > 65535 {
					errs = append(errs, fmt.Sprintf("%s: port %d must be between 1 and 65535", field, p))
				}
			}
		}
		validatePortList("discovery.network.http_candidate_ports", n.HTTPCandidatePorts)
		validatePortList("discovery.network.ai_candidate_ports", n.AICandidatePorts)
		for name, profile := range n.Profiles {
			if len(profile.Ports) == 0 {
				errs = append(errs, fmt.Sprintf("discovery.network.profiles.%s.ports must not be empty", name))
			}
			validatePortList(fmt.Sprintf("discovery.network.profiles.%s.ports", name), profile.Ports)
		}
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
