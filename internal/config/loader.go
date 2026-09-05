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

	// Same scalars-only-via-env convention as discovery.http above —
	// http_candidate_ports/ai_candidate_ports/profiles are YAML-only.
	envDiscoveryNetworkEnabled           = "AI_RECON_DISCOVERY_NETWORK_ENABLED"
	envDiscoveryNetworkConnectTimeout    = "AI_RECON_DISCOVERY_NETWORK_CONNECT_TIMEOUT"
	envDiscoveryNetworkMaxConcurrency    = "AI_RECON_DISCOVERY_NETWORK_MAX_CONCURRENCY"
	envDiscoveryNetworkMaxHosts          = "AI_RECON_DISCOVERY_NETWORK_MAX_HOSTS"
	envDiscoveryNetworkRequestsPerSecond = "AI_RECON_DISCOVERY_NETWORK_REQUESTS_PER_SECOND"

	// Same scalars-only-via-env convention — resolvers/record_types/
	// subdomains.wordlist/profiles are YAML-only.
	envDiscoveryDNSEnabled           = "AI_RECON_DISCOVERY_DNS_ENABLED"
	envDiscoveryDNSTimeout           = "AI_RECON_DISCOVERY_DNS_TIMEOUT"
	envDiscoveryDNSMaxConcurrency    = "AI_RECON_DISCOVERY_DNS_MAX_CONCURRENCY"
	envDiscoveryDNSReversePTR        = "AI_RECON_DISCOVERY_DNS_REVERSE_PTR"
	envDiscoveryDNSRequestsPerSecond = "AI_RECON_DISCOVERY_DNS_REQUESTS_PER_SECOND"
	envDiscoveryDNSSubdomainsEnabled = "AI_RECON_DISCOVERY_DNS_SUBDOMAINS_ENABLED"
	envDiscoveryDNSMaxCandidates     = "AI_RECON_DISCOVERY_DNS_MAX_CANDIDATES"
	envDiscoveryDNSMaxDepth          = "AI_RECON_DISCOVERY_DNS_MAX_DEPTH"

	// Same scalars-only-via-env convention — profiles/seed_paths/
	// sensitive_parameters are YAML-only.
	envDiscoveryEndpointEnabled           = "AI_RECON_DISCOVERY_ENDPOINT_ENABLED"
	envDiscoveryEndpointTimeout           = "AI_RECON_DISCOVERY_ENDPOINT_TIMEOUT"
	envDiscoveryEndpointMaxConcurrency    = "AI_RECON_DISCOVERY_ENDPOINT_MAX_CONCURRENCY"
	envDiscoveryEndpointRequestsPerSecond = "AI_RECON_DISCOVERY_ENDPOINT_REQUESTS_PER_SECOND"
	envDiscoveryEndpointMaxDepth          = "AI_RECON_DISCOVERY_ENDPOINT_MAX_DEPTH"
	envDiscoveryEndpointMaxPages          = "AI_RECON_DISCOVERY_ENDPOINT_MAX_PAGES"
	envDiscoveryEndpointMaxEndpoints      = "AI_RECON_DISCOVERY_ENDPOINT_MAX_ENDPOINTS"
	envDiscoveryEndpointEnableRobots      = "AI_RECON_DISCOVERY_ENDPOINT_ENABLE_ROBOTS"
	envDiscoveryEndpointEnableSitemap     = "AI_RECON_DISCOVERY_ENDPOINT_ENABLE_SITEMAP"
	envDiscoveryEndpointEnableJavaScript  = "AI_RECON_DISCOVERY_ENDPOINT_ENABLE_JAVASCRIPT"
	envDiscoveryEndpointEnableOpenAPI     = "AI_RECON_DISCOVERY_ENDPOINT_ENABLE_OPENAPI"

	envFingerprintEnabled                   = "AI_RECON_FINGERPRINT_ENABLED"
	envFingerprintSignaturesPath            = "AI_RECON_FINGERPRINT_SIGNATURES_PATH"
	envFingerprintMinConfidence             = "AI_RECON_FINGERPRINT_MIN_CONFIDENCE"
	envFingerprintConfidenceChangeThreshold = "AI_RECON_FINGERPRINT_CONFIDENCE_CHANGE_THRESHOLD"
	envFingerprintHistoricalTracking        = "AI_RECON_FINGERPRINT_HISTORICAL_TRACKING"
	envFingerprintDetectChanges             = "AI_RECON_FINGERPRINT_DETECT_CHANGES"

	envDetectionEnabled               = "AI_RECON_DETECTION_ENABLED"
	envDetectionMode                  = "AI_RECON_DETECTION_MODE"
	envDetectionTimeout               = "AI_RECON_DETECTION_TIMEOUT"
	envDetectionMaxResponseSize       = "AI_RECON_DETECTION_MAX_RESPONSE_SIZE"
	envDetectionMaxExcerptSize        = "AI_RECON_DETECTION_MAX_EXCERPT_SIZE"
	envDetectionCertificateExpiryDays = "AI_RECON_DETECTION_CERTIFICATE_EXPIRY_DAYS"

	envInvestigationEnabled            = "AI_RECON_INVESTIGATION_ENABLED"
	envInvestigationCorrelationEnabled = "AI_RECON_INVESTIGATION_CORRELATION_ENABLED"
	envInvestigationThreshold          = "AI_RECON_INVESTIGATION_CORRELATION_THRESHOLD"
	envInvestigationTemporalWindow     = "AI_RECON_INVESTIGATION_CORRELATION_TEMPORAL_WINDOW"

	envIntelligenceEnabled              = "AI_RECON_INTELLIGENCE_ENABLED"
	envIntelligenceExternalEnabled      = "AI_RECON_INTELLIGENCE_EXTERNAL_ENABLED"
	envIntelligenceProviderTimeout      = "AI_RECON_INTELLIGENCE_PROVIDER_TIMEOUT"
	envIntelligenceReputationTTL        = "AI_RECON_INTELLIGENCE_REPUTATION_TTL"
	envIntelligenceVulnerabilityTTL     = "AI_RECON_INTELLIGENCE_VULNERABILITY_TTL"
	envIntelligenceThreatFeedBaseURL    = "AI_RECON_INTELLIGENCE_THREAT_FEED_BASE_URL"
	envIntelligenceThreatFeedAPIKeyEnv  = "AI_RECON_INTELLIGENCE_THREAT_FEED_API_KEY_ENV"
	envIntelligenceThreatFeedRPS        = "AI_RECON_INTELLIGENCE_THREAT_FEED_REQUESTS_PER_SECOND"
	envIntelligenceThreatFeedMaxRetries = "AI_RECON_INTELLIGENCE_THREAT_FEED_MAX_RETRIES"

	envDetectionRulesEnabled            = "AI_RECON_DETECTION_RULES_ENABLED"
	envDetectionRulesMaxConcurrency     = "AI_RECON_DETECTION_RULES_MAX_CONCURRENCY"
	envDetectionRulesTimeout            = "AI_RECON_DETECTION_RULES_TIMEOUT"
	envDetectionRulesClockSkew          = "AI_RECON_DETECTION_RULES_CLOCK_SKEW"
	envDetectionRulesSuppressionWindow  = "AI_RECON_DETECTION_RULES_SUPPRESSION_DEFAULT_WINDOW"
	envDetectionRulesHistoricalMaxRange = "AI_RECON_DETECTION_RULES_HISTORICAL_MAX_RANGE"

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
			Network: NetworkDiscoveryConfig{
				Enabled:            true,
				ConnectTimeout:     2 * time.Second,
				MaxConcurrency:     100,
				MaxHosts:           256,
				RequestsPerSecond:  0, // unlimited by default; MaxConcurrency + ConnectTimeout are the primary safety bounds
				HTTPCandidatePorts: []int{80, 443, 8000, 8080, 8443},
				AICandidatePorts:   []int{11434, 5000, 8000, 8080, 8888},
				Profiles: map[string]NetworkProfileConfig{
					"quick": {
						Ports: []int{80, 443, 8000, 8080, 8443, 8888, 11434},
					},
					"standard": {
						Ports: []int{22, 80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 11434},
					},
					"comprehensive": {
						Ports: []int{
							21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
							1433, 1521, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
							8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090,
							9200, 9300, 11211, 11434, 27017, 50000,
						},
					},
				},
			},
			DNS: DNSDiscoveryConfig{
				Enabled:           true,
				Timeout:           3 * time.Second,
				MaxConcurrency:    20,
				Resolvers:         nil, // empty = system resolver
				RecordTypes:       []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"},
				ReversePTR:        true,
				RequestsPerSecond: 0,
				Subdomains: DNSSubdomainConfig{
					Enabled:       true,
					MaxCandidates: 10000,
					Wordlist:      "",
					Words: []string{
						"api", "app", "dev", "staging", "test", "admin",
						"portal", "chat", "model", "models", "inference",
						"llm", "ai", "ml",
					},
					WildcardDetection: true,
					// A conservative base default — depth-1 only. Combining
					// even a modest wordlist at depth 3 explodes
					// combinatorially (14 words -> 14 + 196 + 2744 = 2954
					// candidates); an operator opts into deeper enumeration
					// explicitly via --max-depth or a profile that raises it
					// (see "comprehensive" below), matching this project's
					// safe-by-default convention throughout every phase.
					MaxDepth: 1,
				},
				Profiles: map[string]DNSProfileConfig{
					"quick": {
						RecordTypes:    []string{"A", "AAAA", "CNAME", "NS", "MX", "SOA"},
						SubdomainWords: []string{"api", "www", "app", "dev", "admin"},
						MaxDepth:       1, // "a small high-value set" — never broad enumeration (phase5.md §50)
					},
					"standard": {
						RecordTypes: []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"},
						SubdomainWords: []string{
							"api", "www", "app", "dev", "staging", "test", "admin",
							"portal", "chat", "model", "models", "inference", "llm",
							"ai", "ml", "mail", "ftp", "vpn", "secure", "beta",
						},
						MaxDepth: 1,
					},
					"comprehensive": {
						RecordTypes: []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"},
						SubdomainWords: []string{
							"api", "www", "app", "dev", "staging", "test", "admin",
							"portal", "chat", "model", "models", "inference", "llm",
							"ai", "ml", "mail", "ftp", "vpn", "secure", "beta",
							"auth", "gateway", "internal", "private", "backend",
							"service", "static", "cdn", "assets", "docs", "status",
							"monitor", "grafana", "prometheus", "jenkins", "gitlab",
							"git", "ci", "cd", "k8s", "kube", "docker", "registry",
							"npm", "pypi", "old", "legacy", "sandbox", "demo", "qa",
						},
						MaxDepth: 2, // deeper combination space, still explicitly bounded (phase5.md §52) — not depth 3's ~130k-candidate explosion by default
					},
				},
			},
			Endpoint: EndpointDiscoveryConfig{
				Enabled:           true,
				Timeout:           10 * time.Second,
				MaxConcurrency:    10,
				RequestsPerSecond: 0,
				MaxResponseSize:   2 * 1024 * 1024, // 2 MiB (phase7.md §24's own worked example)
				MaxDepth:          2,
				MaxPages:          100,
				MaxEndpoints:      1000,
				FollowRedirects:   true,
				MaxRedirects:      5,
				EnableRobots:      true,
				EnableSitemap:     true,
				EnableJavaScript:  true,
				EnableOpenAPI:     true,
				MaxSitemaps:       10,
				MaxSitemapURLs:    1000,
				SeedPaths:         []string{"/"},
				SensitiveParameters: []string{
					"token", "access_token", "refresh_token", "api_key", "apikey",
					"key", "password", "passwd", "secret", "signature", "session",
					"code", "authorization",
				},
				Profiles: map[string]EndpointProfileConfig{
					"quick": {
						MaxDepth: 1, MaxPages: 20, MaxEndpoints: 200,
						EnableRobots: false, EnableSitemap: false, EnableJavaScript: false, EnableOpenAPI: true,
					},
					"standard": {
						MaxDepth: 2, MaxPages: 100, MaxEndpoints: 1000,
						EnableRobots: true, EnableSitemap: true, EnableJavaScript: true, EnableOpenAPI: true,
					},
					"comprehensive": {
						MaxDepth: 3, MaxPages: 500, MaxEndpoints: 5000,
						EnableRobots: true, EnableSitemap: true, EnableJavaScript: true, EnableOpenAPI: true,
					},
				},
			},
		},
		Fingerprint: FingerprintConfig{
			Enabled:                   true,
			MinConfidence:             0.30, // matches internal/fingerprint.DefaultThresholds' "low" boundary — below this, a match isn't worth reporting at all
			ConfidenceChangeThreshold: 0.10,
			HistoricalTracking:        true,
			DetectChanges:             true,
			RedactSensitiveData:       true,
		},
		Detection: DetectionConfig{
			Enabled: true,
			Mode:    "passive",
			Evidence: DetectionEvidenceConfig{
				MaxExcerptSize: 2048,
			},
			Thresholds: DetectionThresholdsConfig{
				CertificateExpiryDays: 14,
			},
			Timeout:         10 * time.Second,
			MaxResponseSize: 262144,
		},
		Investigation: InvestigationConfig{
			Enabled: true,
			Correlation: InvestigationCorrelationConfig{
				Enabled:        true,
				Threshold:      60,
				TemporalWindow: 5 * time.Minute,
			},
		},
		Intelligence: IntelligenceConfig{
			Enabled: true,
			// External enrichment defaults to disabled — the
			// conservative default phase10.md §29 requires; an
			// operator must explicitly opt in per-deployment.
			External: IntelligenceExternalConfig{Enabled: false},
			Providers: map[string]bool{
				"local": true, "dns": true, "certificate": true, "technology": true, "threat_feed": true,
			},
			ProviderTimeout:  10 * time.Second,
			ReputationTTL:    24 * time.Hour,
			VulnerabilityTTL: 7 * 24 * time.Hour,
			ThreatFeed: IntelligenceThreatFeedConfig{
				RequestsPerSecond: 1,
				MaxRetries:        0,
			},
			// Risk.Weights is left zero-valued here — internal/
			// intelligence/risk.DefaultWeights() applies whenever
			// every field is zero (see risk.NewScorer), the same
			// all-or-nothing override convention
			// FingerprintConfig.Thresholds already uses: an operator
			// customizing weights must supply the complete set via
			// YAML, not a partial override.
		},
		DetectionRules: RuleEngineConfig{
			Enabled: true,
			Evaluation: RuleEvaluationConfig{
				MaxConcurrency: 4,
				Timeout:        30 * time.Second,
				ClockSkew:      2 * time.Minute,
			},
			SuppressionDefaultWindow: 15 * time.Minute,
			Historical: RuleHistoricalConfig{
				MaxRange: 24 * time.Hour,
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
	setFloat64 := func(key string, dst *float64) {
		if v, ok := os.LookupEnv(key); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: invalid number %q", key, v))
				return
			}
			*dst = f
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

	setBool(envDiscoveryNetworkEnabled, &cfg.Discovery.Network.Enabled)
	setDuration(envDiscoveryNetworkConnectTimeout, &cfg.Discovery.Network.ConnectTimeout)
	setInt(envDiscoveryNetworkMaxConcurrency, &cfg.Discovery.Network.MaxConcurrency)
	setInt(envDiscoveryNetworkMaxHosts, &cfg.Discovery.Network.MaxHosts)
	setFloat64(envDiscoveryNetworkRequestsPerSecond, &cfg.Discovery.Network.RequestsPerSecond)

	setBool(envDiscoveryDNSEnabled, &cfg.Discovery.DNS.Enabled)
	setDuration(envDiscoveryDNSTimeout, &cfg.Discovery.DNS.Timeout)
	setInt(envDiscoveryDNSMaxConcurrency, &cfg.Discovery.DNS.MaxConcurrency)
	setBool(envDiscoveryDNSReversePTR, &cfg.Discovery.DNS.ReversePTR)
	setFloat64(envDiscoveryDNSRequestsPerSecond, &cfg.Discovery.DNS.RequestsPerSecond)
	setBool(envDiscoveryDNSSubdomainsEnabled, &cfg.Discovery.DNS.Subdomains.Enabled)
	setInt(envDiscoveryDNSMaxCandidates, &cfg.Discovery.DNS.Subdomains.MaxCandidates)
	setInt(envDiscoveryDNSMaxDepth, &cfg.Discovery.DNS.Subdomains.MaxDepth)

	setBool(envDiscoveryEndpointEnabled, &cfg.Discovery.Endpoint.Enabled)
	setDuration(envDiscoveryEndpointTimeout, &cfg.Discovery.Endpoint.Timeout)
	setInt(envDiscoveryEndpointMaxConcurrency, &cfg.Discovery.Endpoint.MaxConcurrency)
	setFloat64(envDiscoveryEndpointRequestsPerSecond, &cfg.Discovery.Endpoint.RequestsPerSecond)
	setInt(envDiscoveryEndpointMaxDepth, &cfg.Discovery.Endpoint.MaxDepth)
	setInt(envDiscoveryEndpointMaxPages, &cfg.Discovery.Endpoint.MaxPages)
	setInt(envDiscoveryEndpointMaxEndpoints, &cfg.Discovery.Endpoint.MaxEndpoints)
	setBool(envDiscoveryEndpointEnableRobots, &cfg.Discovery.Endpoint.EnableRobots)
	setBool(envDiscoveryEndpointEnableSitemap, &cfg.Discovery.Endpoint.EnableSitemap)
	setBool(envDiscoveryEndpointEnableJavaScript, &cfg.Discovery.Endpoint.EnableJavaScript)
	setBool(envDiscoveryEndpointEnableOpenAPI, &cfg.Discovery.Endpoint.EnableOpenAPI)

	setBool(envFingerprintEnabled, &cfg.Fingerprint.Enabled)
	setString(envFingerprintSignaturesPath, &cfg.Fingerprint.SignaturesPath)
	setFloat64(envFingerprintMinConfidence, &cfg.Fingerprint.MinConfidence)
	setFloat64(envFingerprintConfidenceChangeThreshold, &cfg.Fingerprint.ConfidenceChangeThreshold)
	setBool(envFingerprintHistoricalTracking, &cfg.Fingerprint.HistoricalTracking)
	setBool(envFingerprintDetectChanges, &cfg.Fingerprint.DetectChanges)

	setBool(envDetectionEnabled, &cfg.Detection.Enabled)
	setString(envDetectionMode, &cfg.Detection.Mode)
	setDuration(envDetectionTimeout, &cfg.Detection.Timeout)
	setInt64(envDetectionMaxResponseSize, &cfg.Detection.MaxResponseSize)
	setInt(envDetectionMaxExcerptSize, &cfg.Detection.Evidence.MaxExcerptSize)
	setInt(envDetectionCertificateExpiryDays, &cfg.Detection.Thresholds.CertificateExpiryDays)

	setBool(envInvestigationEnabled, &cfg.Investigation.Enabled)
	setBool(envInvestigationCorrelationEnabled, &cfg.Investigation.Correlation.Enabled)
	setInt(envInvestigationThreshold, &cfg.Investigation.Correlation.Threshold)
	setDuration(envInvestigationTemporalWindow, &cfg.Investigation.Correlation.TemporalWindow)

	setBool(envIntelligenceEnabled, &cfg.Intelligence.Enabled)
	setBool(envIntelligenceExternalEnabled, &cfg.Intelligence.External.Enabled)
	setDuration(envIntelligenceProviderTimeout, &cfg.Intelligence.ProviderTimeout)
	setDuration(envIntelligenceReputationTTL, &cfg.Intelligence.ReputationTTL)
	setDuration(envIntelligenceVulnerabilityTTL, &cfg.Intelligence.VulnerabilityTTL)
	setString(envIntelligenceThreatFeedBaseURL, &cfg.Intelligence.ThreatFeed.BaseURL)
	setString(envIntelligenceThreatFeedAPIKeyEnv, &cfg.Intelligence.ThreatFeed.APIKeyEnv)
	setFloat64(envIntelligenceThreatFeedRPS, &cfg.Intelligence.ThreatFeed.RequestsPerSecond)
	setInt(envIntelligenceThreatFeedMaxRetries, &cfg.Intelligence.ThreatFeed.MaxRetries)

	setBool(envDetectionRulesEnabled, &cfg.DetectionRules.Enabled)
	setInt(envDetectionRulesMaxConcurrency, &cfg.DetectionRules.Evaluation.MaxConcurrency)
	setDuration(envDetectionRulesTimeout, &cfg.DetectionRules.Evaluation.Timeout)
	setDuration(envDetectionRulesClockSkew, &cfg.DetectionRules.Evaluation.ClockSkew)
	setDuration(envDetectionRulesSuppressionWindow, &cfg.DetectionRules.SuppressionDefaultWindow)
	setDuration(envDetectionRulesHistoricalMaxRange, &cfg.DetectionRules.Historical.MaxRange)

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
