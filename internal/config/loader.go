package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Environment variable names recognized by Load. All configuration
// environment variables are prefixed with AI_RECON_ to avoid colliding
// with unrelated process environment variables.
const (
	EnvVarEnvironment = "AI_RECON_APP_ENV"
	EnvVarConfigDir   = "AI_RECON_CONFIG_DIR"

	envServerHost              = "AI_RECON_SERVER_HOST"
	envServerPort              = "AI_RECON_SERVER_PORT"
	envServerReadHeaderTimeout = "AI_RECON_SERVER_READ_HEADER_TIMEOUT"
	envServerReadTimeout       = "AI_RECON_SERVER_READ_TIMEOUT"
	envServerWriteTimeout      = "AI_RECON_SERVER_WRITE_TIMEOUT"
	envServerIdleTimeout       = "AI_RECON_SERVER_IDLE_TIMEOUT"
	envServerShutdownTimeout   = "AI_RECON_SERVER_SHUTDOWN_TIMEOUT"

	envDatabaseHost               = "AI_RECON_DATABASE_HOST"
	envDatabasePort               = "AI_RECON_DATABASE_PORT"
	envDatabaseUser               = "AI_RECON_DATABASE_USER"
	envDatabasePassword           = "AI_RECON_DATABASE_PASSWORD" //nolint:gosec // this is an env var NAME, not a credential value
	envDatabaseName               = "AI_RECON_DATABASE_NAME"
	envDatabaseSSLMode            = "AI_RECON_DATABASE_SSL_MODE"
	envDatabaseConnectTimeout     = "AI_RECON_DATABASE_CONNECT_TIMEOUT"
	envDatabaseMaxOpenConnections = "AI_RECON_DATABASE_MAX_OPEN_CONNECTIONS"
	envDatabaseMaxIdleConnections = "AI_RECON_DATABASE_MAX_IDLE_CONNECTIONS"
	envDatabaseConnMaxLifetime    = "AI_RECON_DATABASE_CONNECTION_MAX_LIFETIME"
	envDatabaseConnMaxIdleTime    = "AI_RECON_DATABASE_CONNECTION_MAX_IDLE_TIME"

	envRedisAddress        = "AI_RECON_REDIS_ADDRESS"
	envRedisPassword       = "AI_RECON_REDIS_PASSWORD" //nolint:gosec // this is an env var NAME, not a credential value
	envRedisDatabase       = "AI_RECON_REDIS_DATABASE"
	envRedisConnectTimeout = "AI_RECON_REDIS_CONNECT_TIMEOUT"

	envHTTPClientTimeout               = "AI_RECON_HTTP_TIMEOUT"
	envHTTPClientMaxIdleConnections    = "AI_RECON_HTTP_MAX_IDLE_CONNECTIONS"
	envHTTPClientMaxConnectionsPerHost = "AI_RECON_HTTP_MAX_CONNECTIONS_PER_HOST"
	envHTTPClientMaxResponseSize       = "AI_RECON_HTTP_MAX_RESPONSE_SIZE"
	envHTTPClientMaxRedirects          = "AI_RECON_HTTP_MAX_REDIRECTS"

	// Discovery HTTP env overrides cover scalar fields only — methods,
	// schemes, paths, and profiles are structured/list-shaped and are
	// configured exclusively via YAML (configs/*/config.yaml), the same
	// convention every other list-shaped setting in this project follows.
	envDiscoveryHTTPEnabled           = "AI_RECON_DISCOVERY_HTTP_ENABLED"
	envDiscoveryHTTPTimeout           = "AI_RECON_DISCOVERY_HTTP_TIMEOUT"
	envDiscoveryHTTPMaxConcurrency    = "AI_RECON_DISCOVERY_HTTP_MAX_CONCURRENCY"
	envDiscoveryHTTPMaxResponseSize   = "AI_RECON_DISCOVERY_HTTP_MAX_RESPONSE_SIZE"
	envDiscoveryHTTPFollowRedirects   = "AI_RECON_DISCOVERY_HTTP_FOLLOW_REDIRECTS"
	envDiscoveryHTTPMaxRedirects      = "AI_RECON_DISCOVERY_HTTP_MAX_REDIRECTS"
	envDiscoveryHTTPDetectAIEndpoints = "AI_RECON_DISCOVERY_HTTP_DETECT_AI_ENDPOINTS"

	envLoggingLevel  = "AI_RECON_LOG_LEVEL"
	envLoggingFormat = "AI_RECON_LOG_FORMAT"

	envSecurityRequireAuthorization = "AI_RECON_SECURITY_REQUIRE_AUTHORIZATION"
	envSecurityDryRun               = "AI_RECON_SECURITY_DRY_RUN"

	defaultConfigDir   = "configs"
	defaultEnvironment = "development"
)

// defaultConfig returns the built-in, hard-coded defaults. These are the
// lowest-priority layer: every other source (defaults file, environment
// file, env vars, CLI flags) may override them.
func defaultConfig() *Config {
	return &Config{
		Application: ApplicationConfig{
			Name:        "ai-recon-platform",
			Environment: defaultEnvironment,
			Version:     "",
		},
		Server: ServerConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ShutdownTimeout:   15 * time.Second,
		},
		Database: DatabaseConfig{
			Host:               "localhost",
			Port:               5432,
			User:               "airecon",
			Password:           "",
			Name:               "airecon",
			SSLMode:            "disable",
			ConnectTimeout:     5 * time.Second,
			MaxOpenConnections: 20,
			MaxIdleConnections: 10,
			ConnMaxLifetime:    30 * time.Minute,
			ConnMaxIdleTime:    5 * time.Minute,
		},
		Redis: RedisConfig{
			Address:        "localhost:6379",
			Password:       "",
			Database:       0,
			ConnectTimeout: 5 * time.Second,
		},
		HTTPClient: HTTPClientConfig{
			Timeout:               10 * time.Second,
			MaxIdleConnections:    100,
			MaxConnectionsPerHost: 20,
			MaxResponseSize:       10 * 1024 * 1024, // 10 MiB
			MaxRedirects:          5,
		},
		Discovery: DiscoveryConfig{
			HTTP: HTTPDiscoveryConfig{
				Enabled:           true,
				Timeout:           10 * time.Second,
				MaxConcurrency:    10,
				MaxResponseSize:   10 * 1024 * 1024, // 10 MiB
				FollowRedirects:   true,
				MaxRedirects:      5,
				Methods:           []string{"GET"},
				Schemes:           []string{"https", "http"},
				DetectAIEndpoints: true,
				Paths: []string{
					"/", "/robots.txt", "/openapi.json", "/swagger.json",
					"/api", "/api/", "/v1", "/v1/", "/v1/models",
					"/v1/chat/completions", "/v1/completions", "/v1/embeddings",
					"/models", "/health", "/healthz", "/ready", "/status",
				},
				Profiles: map[string]ProfileConfig{
					"quick": {
						Paths: []string{"/", "/robots.txt", "/openapi.json", "/v1/models", "/health"},
					},
					"comprehensive": {
						Paths: []string{
							"/", "/robots.txt", "/openapi.json", "/swagger.json",
							"/api", "/api/", "/v1", "/v1/", "/v1/models",
							"/v1/chat/completions", "/v1/completions", "/v1/embeddings",
							"/models", "/health", "/healthz", "/ready", "/status",
						},
					},
				},
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Security: SecurityConfig{
			RequireAuthorization: true,
			DryRun:               false,
		},
	}
}

// Load builds the effective Config by layering, in increasing priority:
//
//  1. hard-coded defaults (defaultConfig)
//  2. <configDir>/defaults/config.yaml
//  3. <configDir>/<environment>/config.yaml
//  4. AI_RECON_* environment variables
//
// configDir defaults to "configs" and environment defaults to
// "development"; both may be overridden via AI_RECON_CONFIG_DIR /
// AI_RECON_APP_ENV before Load is called. The result is validated before
// being returned. Callers that need command-line flag overrides should
// apply them to the returned Config (see ApplyOverrides) and call Validate
// again.
func Load() (*Config, error) {
	cfg := defaultConfig()

	configDir := defaultConfigDir
	if v, ok := os.LookupEnv(EnvVarConfigDir); ok && strings.TrimSpace(v) != "" {
		configDir = v
	}

	environment := defaultEnvironment
	if v, ok := os.LookupEnv(EnvVarEnvironment); ok && strings.TrimSpace(v) != "" {
		environment = v
	}
	cfg.Application.Environment = environment

	if err := mergeYAMLFile(cfg, filepath.Join(configDir, "defaults", "config.yaml")); err != nil {
		return nil, err
	}
	if err := mergeYAMLFile(cfg, filepath.Join(configDir, environment, "config.yaml")); err != nil {
		return nil, err
	}

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// mergeYAMLFile unmarshals the YAML file at path onto cfg. Fields absent
// from the file are left untouched, so this acts as an overlay rather than
// a replacement. A missing file is not an error: both the defaults and
// environment config files are optional.
func mergeYAMLFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // path is an operator-controlled config directory (AI_RECON_CONFIG_DIR / --config-dir), not external/user input
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading config file %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parsing config file %s: %w", path, err)
	}
	return nil
}

// applyEnvOverrides overlays AI_RECON_* environment variables onto cfg.
func applyEnvOverrides(cfg *Config) error {
	var errs []string

	setString := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok {
			*dst = v
		}
	}
	setInt := func(key string, dst *int) {
		if v, ok := os.LookupEnv(key); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: invalid integer %q", key, v))
				return
			}
			*dst = n
		}
	}
	setInt32 := func(key string, dst *int32) {
		if v, ok := os.LookupEnv(key); ok {
			n, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: invalid integer %q", key, v))
				return
			}
			*dst = int32(n)
		}
	}
	setInt64 := func(key string, dst *int64) {
		if v, ok := os.LookupEnv(key); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: invalid integer %q", key, v))
				return
			}
			*dst = n
		}
	}
	setBool := func(key string, dst *bool) {
		if v, ok := os.LookupEnv(key); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: invalid boolean %q", key, v))
				return
			}
			*dst = b
		}
	}
	setDuration := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv(key); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: invalid duration %q", key, v))
				return
			}
			*dst = d
		}
	}

	setString(envServerHost, &cfg.Server.Host)
	setInt(envServerPort, &cfg.Server.Port)
	setDuration(envServerReadHeaderTimeout, &cfg.Server.ReadHeaderTimeout)
	setDuration(envServerReadTimeout, &cfg.Server.ReadTimeout)
	setDuration(envServerWriteTimeout, &cfg.Server.WriteTimeout)
	setDuration(envServerIdleTimeout, &cfg.Server.IdleTimeout)
	setDuration(envServerShutdownTimeout, &cfg.Server.ShutdownTimeout)

	setString(envDatabaseHost, &cfg.Database.Host)
	setInt(envDatabasePort, &cfg.Database.Port)
	setString(envDatabaseUser, &cfg.Database.User)
	setString(envDatabasePassword, &cfg.Database.Password)
	setString(envDatabaseName, &cfg.Database.Name)
	setString(envDatabaseSSLMode, &cfg.Database.SSLMode)
	setDuration(envDatabaseConnectTimeout, &cfg.Database.ConnectTimeout)
	setInt32(envDatabaseMaxOpenConnections, &cfg.Database.MaxOpenConnections)
	setInt32(envDatabaseMaxIdleConnections, &cfg.Database.MaxIdleConnections)
	setDuration(envDatabaseConnMaxLifetime, &cfg.Database.ConnMaxLifetime)
	setDuration(envDatabaseConnMaxIdleTime, &cfg.Database.ConnMaxIdleTime)

	setString(envRedisAddress, &cfg.Redis.Address)
	setString(envRedisPassword, &cfg.Redis.Password)
	setInt(envRedisDatabase, &cfg.Redis.Database)
	setDuration(envRedisConnectTimeout, &cfg.Redis.ConnectTimeout)

	setDuration(envHTTPClientTimeout, &cfg.HTTPClient.Timeout)
	setInt(envHTTPClientMaxIdleConnections, &cfg.HTTPClient.MaxIdleConnections)
	setInt(envHTTPClientMaxConnectionsPerHost, &cfg.HTTPClient.MaxConnectionsPerHost)
	setInt64(envHTTPClientMaxResponseSize, &cfg.HTTPClient.MaxResponseSize)
	setInt(envHTTPClientMaxRedirects, &cfg.HTTPClient.MaxRedirects)

	setBool(envDiscoveryHTTPEnabled, &cfg.Discovery.HTTP.Enabled)
	setDuration(envDiscoveryHTTPTimeout, &cfg.Discovery.HTTP.Timeout)
	setInt(envDiscoveryHTTPMaxConcurrency, &cfg.Discovery.HTTP.MaxConcurrency)
	setInt64(envDiscoveryHTTPMaxResponseSize, &cfg.Discovery.HTTP.MaxResponseSize)
	setBool(envDiscoveryHTTPFollowRedirects, &cfg.Discovery.HTTP.FollowRedirects)
	setInt(envDiscoveryHTTPMaxRedirects, &cfg.Discovery.HTTP.MaxRedirects)
	setBool(envDiscoveryHTTPDetectAIEndpoints, &cfg.Discovery.HTTP.DetectAIEndpoints)

	setString(envLoggingLevel, &cfg.Logging.Level)
	setString(envLoggingFormat, &cfg.Logging.Format)

	setBool(envSecurityRequireAuthorization, &cfg.Security.RequireAuthorization)
	setBool(envSecurityDryRun, &cfg.Security.DryRun)

	if len(errs) > 0 {
		return fmt.Errorf("invalid environment variables:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// Overrides holds optional command-line flag values. Nil fields are left
// untouched by ApplyOverrides, so only flags the user actually passed take
// effect. This is the highest-priority layer in the configuration
// precedence: defaults -> config files -> environment variables -> flags.
type Overrides struct {
	ServerHost   *string
	ServerPort   *int
	LoggingLevel *string
	DryRun       *bool
}

// ApplyOverrides layers o onto cfg in place.
func ApplyOverrides(cfg *Config, o Overrides) {
	if o.ServerHost != nil {
		cfg.Server.Host = *o.ServerHost
	}
	if o.ServerPort != nil {
		cfg.Server.Port = *o.ServerPort
	}
	if o.LoggingLevel != nil {
		cfg.Logging.Level = *o.LoggingLevel
	}
	if o.DryRun != nil {
		cfg.Security.DryRun = *o.DryRun
	}
}
