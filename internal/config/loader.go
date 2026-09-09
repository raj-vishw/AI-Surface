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
// environment variables are prefixed with AI_SURFACE_ to avoid colliding
// with unrelated process environment variables.
const (
	EnvVarEnvironment = "AI_SURFACE_APP_ENV"
	EnvVarConfigDir   = "AI_SURFACE_CONFIG_DIR"

	envDatabaseHost               = "AI_SURFACE_DATABASE_HOST"
	envDatabasePort               = "AI_SURFACE_DATABASE_PORT"
	envDatabaseUser               = "AI_SURFACE_DATABASE_USER"
	envDatabasePassword           = "AI_SURFACE_DATABASE_PASSWORD" //nolint:gosec // this is an env var NAME, not a credential value
	envDatabaseName               = "AI_SURFACE_DATABASE_NAME"
	envDatabaseSSLMode            = "AI_SURFACE_DATABASE_SSL_MODE"
	envDatabaseConnectTimeout     = "AI_SURFACE_DATABASE_CONNECT_TIMEOUT"
	envDatabaseMaxOpenConnections = "AI_SURFACE_DATABASE_MAX_OPEN_CONNECTIONS"
	envDatabaseMaxIdleConnections = "AI_SURFACE_DATABASE_MAX_IDLE_CONNECTIONS"
	envDatabaseConnMaxLifetime    = "AI_SURFACE_DATABASE_CONNECTION_MAX_LIFETIME"
	envDatabaseConnMaxIdleTime    = "AI_SURFACE_DATABASE_CONNECTION_MAX_IDLE_TIME"

	envRedisAddress        = "AI_SURFACE_REDIS_ADDRESS"
	envRedisPassword       = "AI_SURFACE_REDIS_PASSWORD" //nolint:gosec // this is an env var NAME, not a credential value
	envRedisDatabase       = "AI_SURFACE_REDIS_DATABASE"
	envRedisConnectTimeout = "AI_SURFACE_REDIS_CONNECT_TIMEOUT"

	envHTTPClientTimeout               = "AI_SURFACE_HTTP_TIMEOUT"
	envHTTPClientMaxIdleConnections    = "AI_SURFACE_HTTP_MAX_IDLE_CONNECTIONS"
	envHTTPClientMaxConnectionsPerHost = "AI_SURFACE_HTTP_MAX_CONNECTIONS_PER_HOST"
	envHTTPClientMaxResponseSize       = "AI_SURFACE_HTTP_MAX_RESPONSE_SIZE"
	envHTTPClientMaxRedirects          = "AI_SURFACE_HTTP_MAX_REDIRECTS"

	// Discovery HTTP env overrides cover scalar fields only — methods,
	// schemes, paths, and profiles are structured/list-shaped and are
	// configured exclusively via YAML (configs/*/config.yaml), the same
	// convention every other list-shaped setting in this project follows.
	envDiscoveryHTTPEnabled           = "AI_SURFACE_DISCOVERY_HTTP_ENABLED"
	envDiscoveryHTTPTimeout           = "AI_SURFACE_DISCOVERY_HTTP_TIMEOUT"
	envDiscoveryHTTPMaxConcurrency    = "AI_SURFACE_DISCOVERY_HTTP_MAX_CONCURRENCY"
	envDiscoveryHTTPMaxResponseSize   = "AI_SURFACE_DISCOVERY_HTTP_MAX_RESPONSE_SIZE"
	envDiscoveryHTTPFollowRedirects   = "AI_SURFACE_DISCOVERY_HTTP_FOLLOW_REDIRECTS"
	envDiscoveryHTTPMaxRedirects      = "AI_SURFACE_DISCOVERY_HTTP_MAX_REDIRECTS"
	envDiscoveryHTTPDetectAIEndpoints = "AI_SURFACE_DISCOVERY_HTTP_DETECT_AI_ENDPOINTS"

	// Same scalars-only-via-env convention as discovery.http above —
	// http_candidate_ports/ai_candidate_ports/profiles are YAML-only.
	envDiscoveryNetworkEnabled           = "AI_SURFACE_DISCOVERY_NETWORK_ENABLED"
	envDiscoveryNetworkConnectTimeout    = "AI_SURFACE_DISCOVERY_NETWORK_CONNECT_TIMEOUT"
	envDiscoveryNetworkMaxConcurrency    = "AI_SURFACE_DISCOVERY_NETWORK_MAX_CONCURRENCY"
	envDiscoveryNetworkMaxHosts          = "AI_SURFACE_DISCOVERY_NETWORK_MAX_HOSTS"
	envDiscoveryNetworkRequestsPerSecond = "AI_SURFACE_DISCOVERY_NETWORK_REQUESTS_PER_SECOND"

	// Same scalars-only-via-env convention — resolvers/record_types/
	// subdomains.wordlist/profiles are YAML-only.
	envDiscoveryDNSEnabled           = "AI_SURFACE_DISCOVERY_DNS_ENABLED"
	envDiscoveryDNSTimeout           = "AI_SURFACE_DISCOVERY_DNS_TIMEOUT"
	envDiscoveryDNSMaxConcurrency    = "AI_SURFACE_DISCOVERY_DNS_MAX_CONCURRENCY"
	envDiscoveryDNSReversePTR        = "AI_SURFACE_DISCOVERY_DNS_REVERSE_PTR"
	envDiscoveryDNSRequestsPerSecond = "AI_SURFACE_DISCOVERY_DNS_REQUESTS_PER_SECOND"
	envDiscoveryDNSSubdomainsEnabled = "AI_SURFACE_DISCOVERY_DNS_SUBDOMAINS_ENABLED"
	envDiscoveryDNSMaxCandidates     = "AI_SURFACE_DISCOVERY_DNS_MAX_CANDIDATES"
	envDiscoveryDNSMaxDepth          = "AI_SURFACE_DISCOVERY_DNS_MAX_DEPTH"

	// Same scalars-only-via-env convention — profiles/seed_paths/
	// sensitive_parameters are YAML-only.
	envDiscoveryEndpointEnabled           = "AI_SURFACE_DISCOVERY_ENDPOINT_ENABLED"
	envDiscoveryEndpointTimeout           = "AI_SURFACE_DISCOVERY_ENDPOINT_TIMEOUT"
	envDiscoveryEndpointMaxConcurrency    = "AI_SURFACE_DISCOVERY_ENDPOINT_MAX_CONCURRENCY"
	envDiscoveryEndpointRequestsPerSecond = "AI_SURFACE_DISCOVERY_ENDPOINT_REQUESTS_PER_SECOND"
	envDiscoveryEndpointMaxDepth          = "AI_SURFACE_DISCOVERY_ENDPOINT_MAX_DEPTH"
	envDiscoveryEndpointMaxPages          = "AI_SURFACE_DISCOVERY_ENDPOINT_MAX_PAGES"
	envDiscoveryEndpointMaxEndpoints      = "AI_SURFACE_DISCOVERY_ENDPOINT_MAX_ENDPOINTS"
	envDiscoveryEndpointEnableRobots      = "AI_SURFACE_DISCOVERY_ENDPOINT_ENABLE_ROBOTS"
	envDiscoveryEndpointEnableSitemap     = "AI_SURFACE_DISCOVERY_ENDPOINT_ENABLE_SITEMAP"
	envDiscoveryEndpointEnableJavaScript  = "AI_SURFACE_DISCOVERY_ENDPOINT_ENABLE_JAVASCRIPT"
	envDiscoveryEndpointEnableOpenAPI     = "AI_SURFACE_DISCOVERY_ENDPOINT_ENABLE_OPENAPI"

	envFingerprintEnabled                   = "AI_SURFACE_FINGERPRINT_ENABLED"
	envFingerprintSignaturesPath            = "AI_SURFACE_FINGERPRINT_SIGNATURES_PATH"
	envFingerprintMinConfidence             = "AI_SURFACE_FINGERPRINT_MIN_CONFIDENCE"
	envFingerprintConfidenceChangeThreshold = "AI_SURFACE_FINGERPRINT_CONFIDENCE_CHANGE_THRESHOLD"
	envFingerprintHistoricalTracking        = "AI_SURFACE_FINGERPRINT_HISTORICAL_TRACKING"
	envFingerprintDetectChanges             = "AI_SURFACE_FINGERPRINT_DETECT_CHANGES"

	envDetectionEnabled               = "AI_SURFACE_DETECTION_ENABLED"
	envDetectionMode                  = "AI_SURFACE_DETECTION_MODE"
	envDetectionTimeout               = "AI_SURFACE_DETECTION_TIMEOUT"
	envDetectionMaxResponseSize       = "AI_SURFACE_DETECTION_MAX_RESPONSE_SIZE"
	envDetectionMaxExcerptSize        = "AI_SURFACE_DETECTION_MAX_EXCERPT_SIZE"
	envDetectionCertificateExpiryDays = "AI_SURFACE_DETECTION_CERTIFICATE_EXPIRY_DAYS"

	envInvestigationEnabled            = "AI_SURFACE_INVESTIGATION_ENABLED"
	envInvestigationCorrelationEnabled = "AI_SURFACE_INVESTIGATION_CORRELATION_ENABLED"
	envInvestigationThreshold          = "AI_SURFACE_INVESTIGATION_CORRELATION_THRESHOLD"
	envInvestigationTemporalWindow     = "AI_SURFACE_INVESTIGATION_CORRELATION_TEMPORAL_WINDOW"

	envIntelligenceEnabled              = "AI_SURFACE_INTELLIGENCE_ENABLED"
	envIntelligenceExternalEnabled      = "AI_SURFACE_INTELLIGENCE_EXTERNAL_ENABLED"
	envIntelligenceProviderTimeout      = "AI_SURFACE_INTELLIGENCE_PROVIDER_TIMEOUT"
	envIntelligenceReputationTTL        = "AI_SURFACE_INTELLIGENCE_REPUTATION_TTL"
	envIntelligenceVulnerabilityTTL     = "AI_SURFACE_INTELLIGENCE_VULNERABILITY_TTL"
	envIntelligenceThreatFeedBaseURL    = "AI_SURFACE_INTELLIGENCE_THREAT_FEED_BASE_URL"
	envIntelligenceThreatFeedAPIKeyEnv  = "AI_SURFACE_INTELLIGENCE_THREAT_FEED_API_KEY_ENV"
	envIntelligenceThreatFeedRPS        = "AI_SURFACE_INTELLIGENCE_THREAT_FEED_REQUESTS_PER_SECOND"
	envIntelligenceThreatFeedMaxRetries = "AI_SURFACE_INTELLIGENCE_THREAT_FEED_MAX_RETRIES"

	envDetectionRulesEnabled            = "AI_SURFACE_DETECTION_RULES_ENABLED"
	envDetectionRulesMaxConcurrency     = "AI_SURFACE_DETECTION_RULES_MAX_CONCURRENCY"
	envDetectionRulesTimeout            = "AI_SURFACE_DETECTION_RULES_TIMEOUT"
	envDetectionRulesClockSkew          = "AI_SURFACE_DETECTION_RULES_CLOCK_SKEW"
	envDetectionRulesSuppressionWindow  = "AI_SURFACE_DETECTION_RULES_SUPPRESSION_DEFAULT_WINDOW"
	envDetectionRulesHistoricalMaxRange = "AI_SURFACE_DETECTION_RULES_HISTORICAL_MAX_RANGE"

	envCorrelationEnabled            = "AI_SURFACE_CORRELATION_ENABLED"
	envCorrelationTemporalWindow     = "AI_SURFACE_CORRELATION_TEMPORAL_DEFAULT_WINDOW"
	envCorrelationGraphMaxDepth      = "AI_SURFACE_CORRELATION_GRAPH_MAX_DEPTH"
	envCorrelationGraphMaxNodes      = "AI_SURFACE_CORRELATION_GRAPH_MAX_NODES"
	envCorrelationGraphMaxEdges      = "AI_SURFACE_CORRELATION_GRAPH_MAX_EDGES"
	envCorrelationWorkersConcurrency = "AI_SURFACE_CORRELATION_WORKERS_MAX_CONCURRENCY"
	envCorrelationHistoricalMaxRange = "AI_SURFACE_CORRELATION_HISTORICAL_MAX_RANGE"
	envCorrelationMaxCandidates      = "AI_SURFACE_CORRELATION_MAX_CANDIDATES"

	envAIEnabled             = "AI_SURFACE_AI_ENABLED"
	envAIProviderName        = "AI_SURFACE_AI_PROVIDER_NAME"
	envAIProviderModel       = "AI_SURFACE_AI_PROVIDER_MODEL"
	envAIProviderEndpoint    = "AI_SURFACE_AI_PROVIDER_ENDPOINT"
	envAIProviderAPIKeyEnv   = "AI_SURFACE_AI_PROVIDER_API_KEY_ENV" //nolint:gosec // this is an env var NAME, not a credential value
	envAIProviderMaxTokens   = "AI_SURFACE_AI_PROVIDER_MAX_TOKENS"  //nolint:gosec // false positive: "tokens" here means LLM output tokens, not a credential
	envAIProviderTemp        = "AI_SURFACE_AI_PROVIDER_TEMPERATURE"
	envAILimitsFactsPerType  = "AI_SURFACE_AI_LIMITS_MAX_CONTEXT_FACTS_PER_TYPE"
	envAILimitsTotalFacts    = "AI_SURFACE_AI_LIMITS_MAX_CONTEXT_FACTS"
	envAILimitsOutputTokens  = "AI_SURFACE_AI_LIMITS_MAX_OUTPUT_TOKENS" //nolint:gosec // false positive: "tokens" here means LLM output tokens, not a credential
	envAITimeoutRequest      = "AI_SURFACE_AI_TIMEOUTS_REQUEST"
	envAITimeoutTool         = "AI_SURFACE_AI_TIMEOUTS_TOOL"
	envAIRetriesMax          = "AI_SURFACE_AI_RETRIES_MAX"
	envAIRetriesBackoff      = "AI_SURFACE_AI_RETRIES_BACKOFF"
	envAIRateLimitPerUser    = "AI_SURFACE_AI_RATE_LIMIT_PER_USER_PER_MINUTE"
	envAIRateLimitPerTarget  = "AI_SURFACE_AI_RATE_LIMIT_PER_TARGET_PER_MINUTE"
	envAIRateLimitConcurrent = "AI_SURFACE_AI_RATE_LIMIT_MAX_CONCURRENT"

	envLoggingLevel  = "AI_SURFACE_LOG_LEVEL"
	envLoggingFormat = "AI_SURFACE_LOG_FORMAT"

	envSecurityRequireAuthorization = "AI_SURFACE_SECURITY_REQUIRE_AUTHORIZATION"
	envSecurityDryRun               = "AI_SURFACE_SECURITY_DRY_RUN"

	defaultConfigDir   = "configs"
	defaultEnvironment = "development"
)

// defaultConfig returns the built-in, hard-coded defaults. These are the
// lowest-priority layer: every other source (defaults file, environment
// file, env vars, CLI flags) may override them.
func defaultConfig() *Config {
	return &Config{
		Application: ApplicationConfig{
			Name:        "ai-surface-platform",
			Environment: defaultEnvironment,
			Version:     "",
		},
		Database: DatabaseConfig{
			Host:               "localhost",
			Port:               5432,
			User:               "aisurface",
			Password:           "",
			Name:               "aisurface",
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
		Correlation: CorrelationConfig{
			Enabled: true,
			Temporal: CorrelationTemporalConfig{
				DefaultWindow: 15 * time.Minute,
			},
			Graph: CorrelationGraphConfig{
				MaxDepth: 5,
				MaxNodes: 500,
				MaxEdges: 1000,
			},
			Workers: CorrelationWorkersConfig{
				MaxConcurrency: 4,
			},
			HistoricalMaxRange: 24 * time.Hour,
			MaxCandidates:      2000,
		},
		AI: AIConfig{
			// Disabled by default (phase13.md §85) — an operator must
			// explicitly enable this section for production use.
			Enabled: false,
			Provider: AIProviderConfig{
				Name: "mock", Model: "default", MaxTokens: 2000, Temperature: 0.2,
			},
			Limits: AILimitsConfig{
				MaxFactsPerType: 25, MaxTotalFacts: 100, MaxOutputTokens: 2000,
			},
			Timeouts: AITimeoutsConfig{
				Request: 30 * time.Second, Tool: 5 * time.Second,
			},
			Retries: AIRetriesConfig{
				Max: 1, Backoff: 500 * time.Millisecond,
			},
			RateLimit: AIRateLimitConfig{
				PerUserPerMinute: 20, PerTargetPerMinute: 60, MaxConcurrent: 4,
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
//  4. AI_SURFACE_* environment variables
//
// configDir defaults to "configs" and environment defaults to
// "development"; both may be overridden via AI_SURFACE_CONFIG_DIR /
// AI_SURFACE_APP_ENV before Load is called. The result is validated before
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
	data, err := os.ReadFile(path) //nolint:gosec // path is an operator-controlled config directory (AI_SURFACE_CONFIG_DIR / --config-dir), not external/user input
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

// applyEnvOverrides overlays AI_SURFACE_* environment variables onto cfg.
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

	setBool(envCorrelationEnabled, &cfg.Correlation.Enabled)
	setDuration(envCorrelationTemporalWindow, &cfg.Correlation.Temporal.DefaultWindow)
	setInt(envCorrelationGraphMaxDepth, &cfg.Correlation.Graph.MaxDepth)
	setInt(envCorrelationGraphMaxNodes, &cfg.Correlation.Graph.MaxNodes)
	setInt(envCorrelationGraphMaxEdges, &cfg.Correlation.Graph.MaxEdges)
	setInt(envCorrelationWorkersConcurrency, &cfg.Correlation.Workers.MaxConcurrency)
	setDuration(envCorrelationHistoricalMaxRange, &cfg.Correlation.HistoricalMaxRange)
	setInt(envCorrelationMaxCandidates, &cfg.Correlation.MaxCandidates)

	setBool(envAIEnabled, &cfg.AI.Enabled)
	setString(envAIProviderName, &cfg.AI.Provider.Name)
	setString(envAIProviderModel, &cfg.AI.Provider.Model)
	setString(envAIProviderEndpoint, &cfg.AI.Provider.Endpoint)
	setString(envAIProviderAPIKeyEnv, &cfg.AI.Provider.APIKeyEnv)
	setInt(envAIProviderMaxTokens, &cfg.AI.Provider.MaxTokens)
	setFloat64(envAIProviderTemp, &cfg.AI.Provider.Temperature)
	setInt(envAILimitsFactsPerType, &cfg.AI.Limits.MaxFactsPerType)
	setInt(envAILimitsTotalFacts, &cfg.AI.Limits.MaxTotalFacts)
	setInt(envAILimitsOutputTokens, &cfg.AI.Limits.MaxOutputTokens)
	setDuration(envAITimeoutRequest, &cfg.AI.Timeouts.Request)
	setDuration(envAITimeoutTool, &cfg.AI.Timeouts.Tool)
	setInt(envAIRetriesMax, &cfg.AI.Retries.Max)
	setDuration(envAIRetriesBackoff, &cfg.AI.Retries.Backoff)
	setInt(envAIRateLimitPerUser, &cfg.AI.RateLimit.PerUserPerMinute)
	setInt(envAIRateLimitPerTarget, &cfg.AI.RateLimit.PerTargetPerMinute)
	setInt(envAIRateLimitConcurrent, &cfg.AI.RateLimit.MaxConcurrent)

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
	LoggingLevel *string
	DryRun       *bool
}

// ApplyOverrides layers o onto cfg in place.
func ApplyOverrides(cfg *Config, o Overrides) {
	if o.LoggingLevel != nil {
		cfg.Logging.Level = *o.LoggingLevel
	}
	if o.DryRun != nil {
		cfg.Security.DryRun = *o.DryRun
	}
}
