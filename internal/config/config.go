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
	Application    ApplicationConfig   `yaml:"application"`
	Server         ServerConfig        `yaml:"server"`
	Database       DatabaseConfig      `yaml:"database"`
	Redis          RedisConfig         `yaml:"redis"`
	HTTPClient     HTTPClientConfig    `yaml:"http_client"`
	Discovery      DiscoveryConfig     `yaml:"discovery"`
	Fingerprint    FingerprintConfig   `yaml:"fingerprint"`
	Detection      DetectionConfig     `yaml:"detection"`
	Investigation  InvestigationConfig `yaml:"investigation"`
	Intelligence   IntelligenceConfig  `yaml:"intelligence"`
	DetectionRules RuleEngineConfig    `yaml:"detection_rules"`
	Correlation    CorrelationConfig   `yaml:"correlation"`
	AI             AIConfig            `yaml:"ai"`
	Logging        LoggingConfig       `yaml:"logging"`
	Security       SecurityConfig      `yaml:"security"`
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
// added HTTP; Phase 4 added Network (TCP connect scanning); Phase 5 adds
// DNS. Later phases add further siblings here, not new top-level config
// sections.
type DiscoveryConfig struct {
	HTTP     HTTPDiscoveryConfig     `yaml:"http"`
	Network  NetworkDiscoveryConfig  `yaml:"network"`
	DNS      DNSDiscoveryConfig      `yaml:"dns"`
	Endpoint EndpointDiscoveryConfig `yaml:"endpoint"`
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

// DNSProfileConfig names one reusable record-type + subdomain-wordlist
// combination a DNS scan can be run with ("quick"/"standard"/
// "comprehensive" — see internal/discovery/dns). Data-only, same
// rationale as ProfileConfig/NetworkProfileConfig.
type DNSProfileConfig struct {
	RecordTypes    []string `yaml:"record_types"`
	SubdomainWords []string `yaml:"subdomain_words"`
	// MaxDepth overrides discovery.dns.subdomains.max_depth for this
	// profile; 0 means "use the base max_depth". This exists so "quick"
	// can stay at depth 1 (phase5.md §50: "do not perform broad
	// enumeration") while "comprehensive" uses a deeper combination space
	// (§52), without one shared setting forcing every profile to the same
	// depth.
	MaxDepth int `yaml:"max_depth"`
}

// DNSSubdomainConfig configures subdomain enumeration specifically —
// separate from record-type discovery, per phase5.md §1's explicit
// requirement that the two concepts not be mixed.
type DNSSubdomainConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxCandidates bounds how many subdomain candidates are ever
	// resolved in one scan, regardless of how large the wordlist or how
	// deep MaxDepth allows — exceeding it truncates the candidate list
	// (deterministically, not silently unbounded), never queries more
	// (phase5.md §23).
	MaxCandidates int `yaml:"max_candidates"`
	// Wordlist is a path to a newline-delimited file of candidate labels.
	// Empty means "use Words below (or the selected profile's
	// SubdomainWords, which take precedence when a profile is given)".
	Wordlist string `yaml:"wordlist"`
	// Words is the built-in default candidate label list, used when
	// neither Wordlist nor a profile is given. Configurable, never
	// hard-coded as the *only* option (phase5.md §22).
	Words             []string `yaml:"words"`
	WildcardDetection bool     `yaml:"wildcard_detection"`
	// MaxDepth bounds how many label levels of combination are generated
	// from the wordlist (1 = "word.domain", 2 = "word.word.domain", ...)
	// — never unlimited recursive combination (phase5.md §24).
	MaxDepth int `yaml:"max_depth"`
}

// DNSDiscoveryConfig configures the DNS record and subdomain discovery
// engine (internal/discovery/dns). It does not configure a second HTTP
// client or a second database layer — a discovered subdomain may be
// flagged as an HTTP candidate for a later, separate Phase 3 scan, but
// this package never performs an HTTP request itself.
type DNSDiscoveryConfig struct {
	Enabled bool `yaml:"enabled"`
	// Timeout bounds every individual DNS query — never unlimited.
	Timeout        time.Duration `yaml:"timeout"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	// Resolvers are explicit "host:port" DNS servers to query; empty uses
	// the operating system's configured resolver
	// (internal/discovery/dns.SystemResolver). Never required to be a
	// public resolver — tests use a local fixture exclusively.
	Resolvers []string `yaml:"resolvers"`
	// RecordTypes are queried for the target domain itself (and, for a
	// discovered subdomain, that subdomain) — A, AAAA, CNAME, MX, NS, TXT,
	// SOA, CAA. PTR is handled separately (see ReversePTR): it is a
	// reverse (IP -> name) lookup, not a forward query for a domain name,
	// so it doesn't belong in this forward-query list.
	RecordTypes []string `yaml:"record_types"`
	// ReversePTR, when true, additionally attempts a PTR lookup for every
	// A/AAAA address this scan discovers — only addresses already
	// discovered within scope, never unrestricted reverse-DNS scanning
	// (phase5.md §19).
	ReversePTR bool `yaml:"reverse_ptr"`
	// RequestsPerSecond paces DNS queries; 0 means unlimited. A safety/
	// stability control, not stealth/evasion timing (phase5.md §41).
	RequestsPerSecond float64                     `yaml:"requests_per_second"`
	Subdomains        DNSSubdomainConfig          `yaml:"subdomains"`
	Profiles          map[string]DNSProfileConfig `yaml:"profiles"`
}

// EndpointProfileConfig names one reusable endpoint-discovery
// configuration (phase7.md §59: quick/standard/comprehensive) — entirely
// data, never hard-coded crawl behavior. A zero field inherits the base
// EndpointDiscoveryConfig's value (the same "0/empty means inherit"
// convention DNSProfileConfig.MaxDepth established).
type EndpointProfileConfig struct {
	MaxDepth         int  `yaml:"max_depth"`
	MaxPages         int  `yaml:"max_pages"`
	MaxEndpoints     int  `yaml:"max_endpoints"`
	EnableRobots     bool `yaml:"enable_robots"`
	EnableSitemap    bool `yaml:"enable_sitemap"`
	EnableJavaScript bool `yaml:"enable_javascript"`
	EnableOpenAPI    bool `yaml:"enable_openapi"`
}

// EndpointDiscoveryConfig configures Phase 7's endpoint/API discovery
// engine (internal/discovery/endpoint). It reuses HTTPClientConfig's
// underlying transport (internal/httpclient) and HTTP discovery's
// ScopeValidator — this section only adds crawl-specific policy.
type EndpointDiscoveryConfig struct {
	Enabled bool `yaml:"enabled"`

	Timeout        time.Duration `yaml:"timeout"`
	MaxConcurrency int           `yaml:"max_concurrency"`
	// RequestsPerSecond paces crawl requests; 0 means unlimited — a
	// safety/stability control, never stealth timing (phase7.md §56).
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	MaxResponseSize   int64   `yaml:"max_response_size"`

	// MaxDepth bounds how many link-hops from a seed URL the crawler
	// follows (phase7.md §24/§25) — depth 0 is the seed itself.
	MaxDepth int `yaml:"max_depth"`
	// MaxPages bounds how many distinct pages are fetched in one crawl —
	// never unbounded (phase7.md §24/§52).
	MaxPages int `yaml:"max_pages"`
	// MaxEndpoints bounds how many distinct logical endpoints one crawl
	// may record, across every source (crawled pages, robots.txt,
	// sitemap.xml, JavaScript, OpenAPI/Swagger) — the final backstop
	// against unbounded discovery regardless of source.
	MaxEndpoints int `yaml:"max_endpoints"`

	FollowRedirects bool `yaml:"follow_redirects"`
	MaxRedirects    int  `yaml:"max_redirects"`

	// Discovery sources — each independently toggleable (phase7.md §11).
	// HTML link/form extraction has no separate toggle: it is the
	// crawler's basic mechanism and is always on when the engine runs at
	// all (matching every profile in phase7.md §59, "quick" included).
	EnableRobots     bool `yaml:"enable_robots"`
	EnableSitemap    bool `yaml:"enable_sitemap"`
	EnableJavaScript bool `yaml:"enable_javascript"`
	EnableOpenAPI    bool `yaml:"enable_openapi"`

	// MaxSitemaps/MaxSitemapURLs bound sitemap-index recursion and total
	// <loc> entries read (phase7.md §22) — never unlimited.
	MaxSitemaps    int `yaml:"max_sitemaps"`
	MaxSitemapURLs int `yaml:"max_sitemap_urls"`

	// SeedPaths are appended (after normalization/scope-checking) to
	// whatever seed URLs are derived from the target's own known
	// HTTP(S)/service assets (phase7.md §26) — e.g. "/", "/robots.txt".
	SeedPaths []string `yaml:"seed_paths"`

	// SensitiveParameters names query/form parameter fragments whose
	// *values* are always redacted if ever transiently inspected
	// (phase7.md §10) — matched the same case-insensitive-substring way
	// internal/domain/asset's sensitiveKeyFragments already works; this
	// section exists so the list is visible/extensible via configuration
	// rather than only the Go-level default.
	SensitiveParameters []string `yaml:"sensitive_parameters"`

	Profiles map[string]EndpointProfileConfig `yaml:"profiles"`
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

// FingerprintConfig configures Phase 6's passive fingerprinting engine
// (internal/fingerprint / internal/service/fingerprint). It is a
// top-level Config section, not nested under Discovery, because
// fingerprinting is a distinct pipeline stage that runs against
// already-collected evidence rather than performing discovery itself
// (phase6.md §25's pipeline: Discovery -> Evidence Store ->
// Fingerprinting).
type FingerprintConfig struct {
	Enabled bool `yaml:"enabled"`
	// SignaturesPath, if set, points at an external directory of
	// "*.yaml" signature files to use INSTEAD of the platform's built-in
	// set (internal/fingerprint.DefaultSignaturesFS) — empty uses the
	// built-in set.
	SignaturesPath string `yaml:"signatures_path"`
	// MinConfidence filters out any engine match below this score
	// (phase6.md §32's "minimum score"); a signature's own min_score
	// (see internal/fingerprint.Signature), if higher, still applies on
	// top of this.
	MinConfidence float64 `yaml:"min_confidence"`
	// ConfidenceChangeThreshold is the minimum confidence delta between
	// two analysis runs required to report a "confidence_changed" change
	// — see internal/service/fingerprint.Config (phase6.md §23).
	ConfidenceChangeThreshold float64    `yaml:"confidence_change_threshold"`
	Thresholds                Thresholds `yaml:"thresholds"`
	// HistoricalTracking/DetectChanges are documented, honored toggles:
	// historical fingerprint rows (fingerprint_evidence) are always
	// preserved regardless (phase6.md §22 — "do not delete historical
	// observations" is not optional), but DetectChanges=false skips the
	// Change-computation step entirely (useful for a first-ever scan of
	// a large target, where every match is trivially "added" and the
	// comparison work is pure overhead).
	HistoricalTracking bool `yaml:"historical_tracking"`
	DetectChanges      bool `yaml:"detect_changes"`
	// RedactSensitiveData is always effectively true — Phase 2's
	// SanitizeMetadata redaction boundary is mandatory and not
	// bypassable by configuration (phase6.md §31) — this field exists
	// only so the setting is visible/documented in configuration, the
	// same way security.require_authorization documents a boundary that
	// isn't actually optional either.
	RedactSensitiveData bool `yaml:"redact_sensitive_data"`
}

// Thresholds are the confidence-level bucket boundaries
// (internal/fingerprint.Thresholds's configuration-file mirror —
// phase6.md §8: "these thresholds should be configurable"). The zero
// value means "use internal/fingerprint.DefaultThresholds".
type Thresholds struct {
	Low      float64 `yaml:"low"`
	Medium   float64 `yaml:"medium"`
	High     float64 `yaml:"high"`
	VeryHigh float64 `yaml:"very_high"`
}

// DetectionConfig configures Phase 8's finding/vulnerability detection
// engine (internal/detection / internal/service/detection). Like
// FingerprintConfig, it is a top-level Config section, not nested under
// Discovery — detection is a distinct pipeline stage that runs against
// already-collected evidence (plus, only in safe-active mode, a small set
// of additional bounded requests), never a discovery source itself
// (phase8.md §53's pipeline: discovery -> asset/endpoint inventory ->
// detection engine -> findings).
type DetectionConfig struct {
	Enabled bool `yaml:"enabled"`
	// Mode is "passive" or "safe_active" (phase8.md §54); empty defaults
	// to "passive" — the safe default this project never silently
	// upgrades away from.
	Mode string `yaml:"mode"`
	// Detectors maps a detector id to enabled/disabled (phase8.md §6);
	// absent from the map means enabled. Detector ids match
	// internal/detection/detectors' registered ID() values, e.g.
	// "security_headers.missing-hsts".
	Detectors  map[string]bool           `yaml:"detectors"`
	Evidence   DetectionEvidenceConfig   `yaml:"evidence"`
	Thresholds DetectionThresholdsConfig `yaml:"thresholds"`
	// Timeout/MaxResponseSize bound every safe-active request a detector
	// issues (phase8.md §84); unused entirely in passive mode.
	Timeout         time.Duration `yaml:"timeout"`
	MaxResponseSize int64         `yaml:"max_response_size"`
}

// DetectionEvidenceConfig bounds how much of a response a safe-active
// detector may retain as evidence (phase8.md §9/§27/§56).
type DetectionEvidenceConfig struct {
	MaxExcerptSize int `yaml:"max_excerpt_size"`
}

// DetectionThresholdsConfig configures detector-specific thresholds that
// aren't confidence-level buckets (unlike Thresholds, reused by
// FingerprintConfig) — currently just certificate-expiry warning
// (phase8.md §25/§56).
type DetectionThresholdsConfig struct {
	CertificateExpiryDays int `yaml:"certificate_expiry_days"`
}

var validDetectionModes = map[string]bool{"": true, "passive": true, "safe_active": true}

// InvestigationConfig configures Phase 9's investigation & correlation
// engine (internal/investigation / internal/service/investigation). Like
// DetectionConfig, a top-level Config section rather than nested under
// Discovery — investigation is a distinct pipeline stage that runs
// against already-collected findings/assets/endpoints, never a discovery
// source itself.
type InvestigationConfig struct {
	Enabled     bool                           `yaml:"enabled"`
	Correlation InvestigationCorrelationConfig `yaml:"correlation"`
}

// InvestigationCorrelationConfig configures the correlation engine
// specifically (phase9.md §79).
type InvestigationCorrelationConfig struct {
	Enabled bool `yaml:"enabled"`
	// Threshold is the minimum score for a relationship to be recorded
	// as confirmed rather than a candidate (phase9.md §37). 0 uses
	// internal/investigation.DefaultThreshold.
	Threshold int `yaml:"threshold"`
	// TemporalWindow bounds temporal-proximity signal (phase9.md §16). 0
	// uses internal/investigation.DefaultTemporalWindow.
	TemporalWindow time.Duration `yaml:"temporal_window"`
	// Rules maps a rule id to enabled/disabled; absent means enabled.
	Rules map[string]bool `yaml:"rules"`
}

// IntelligenceConfig configures Phase 10's threat intelligence & risk
// enrichment engine (internal/intelligence / internal/service/
// intelligence). Like InvestigationConfig, a top-level Config section —
// intelligence enrichment is a distinct pipeline stage that runs against
// already-persisted assets/findings/technologies, never a discovery
// source itself.
type IntelligenceConfig struct {
	Enabled bool `yaml:"enabled"`
	// External gates every provider capable of a network request off
	// this platform (phase10.md §29/§30). Conservative default: false.
	External IntelligenceExternalConfig `yaml:"external"`
	// Providers maps a provider id to enabled/disabled — absent means
	// enabled, the same "closed set of explicit opt-outs" convention
	// detection.Config.Detectors/investigation.Config.Rules use.
	Providers map[string]bool `yaml:"providers"`
	// ProviderTimeout bounds each individual provider's Lookup call. <= 0
	// uses intelligence.DefaultProviderTimeout.
	ProviderTimeout time.Duration `yaml:"provider_timeout"`
	// ReputationTTL/VulnerabilityTTL are the intelligence cache's TTLs
	// (phase10.md §22). <= 0 uses intelligence.DefaultReputationTTL /
	// DefaultVulnerabilityTTL.
	ReputationTTL    time.Duration `yaml:"reputation_ttl"`
	VulnerabilityTTL time.Duration `yaml:"vulnerability_ttl"`
	// ThreatFeed configures the one external, opt-in provider
	// (phase10.md §17/§26/§27) — see internal/intelligence/providers.
	// ThreatFeedProvider.
	ThreatFeed IntelligenceThreatFeedConfig `yaml:"threat_feed"`
	Risk       IntelligenceRiskConfig       `yaml:"risk"`
}

// IntelligenceExternalConfig is intelligence.enabled's own external
// enrichment opt-in (phase10.md §29/§73) — a project/target-level
// switch, independent of any individual provider's own enabled flag;
// both must be true for an external provider to ever run.
type IntelligenceExternalConfig struct {
	Enabled bool `yaml:"enabled"`
}

// IntelligenceThreatFeedConfig configures
// internal/intelligence/providers.ThreatFeedProvider. BaseURL/APIKeyEnv
// are operator-supplied — no vendor is hard-coded, and the credential
// itself is never stored in configuration (phase10.md §26).
type IntelligenceThreatFeedConfig struct {
	BaseURL           string  `yaml:"base_url"`
	APIKeyEnv         string  `yaml:"api_key_env"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	MaxRetries        int     `yaml:"max_retries"`
}

// IntelligenceRiskConfig configures the risk-scoring model's weights
// (phase10.md §44 — "document the weights", "do not silently change
// weights"). A zero-valued Weights uses risk.DefaultWeights.
type IntelligenceRiskConfig struct {
	Weights IntelligenceRiskWeightsConfig `yaml:"weights"`
}

// IntelligenceRiskWeightsConfig mirrors internal/intelligence/risk.
// Weights field-for-field (independent copy, same "config.go never
// imports an engine package" boundary DetectionThresholdsConfig/
// InvestigationCorrelationConfig already establish).
type IntelligenceRiskWeightsConfig struct {
	FindingSeverityCritical      int `yaml:"finding_severity_critical"`
	FindingSeverityHigh          int `yaml:"finding_severity_high"`
	FindingSeverityMedium        int `yaml:"finding_severity_medium"`
	FindingSeverityLow           int `yaml:"finding_severity_low"`
	FindingSeverityInformational int `yaml:"finding_severity_informational"`
	FindingConfidenceHigh        int `yaml:"finding_confidence_high"`

	ExposureInternetFacing     int `yaml:"exposure_internet_facing"`
	ExposureOpenServicePerUnit int `yaml:"exposure_open_service_per_unit"`
	ExposureOpenServiceMax     int `yaml:"exposure_open_service_max"`
	ExposureSensitiveEndpoint  int `yaml:"exposure_sensitive_endpoint"`
	ExposureExposedAPI         int `yaml:"exposure_exposed_api"`

	VulnerabilityConfirmed int `yaml:"vulnerability_confirmed"`
	VulnerabilityProbable  int `yaml:"vulnerability_probable"`

	IntelligenceMalicious  int `yaml:"intelligence_malicious"`
	IntelligenceSuspicious int `yaml:"intelligence_suspicious"`

	AssetCriticalityCritical int `yaml:"asset_criticality_critical"`
	AssetCriticalityHigh     int `yaml:"asset_criticality_high"`
	AssetCriticalityNormal   int `yaml:"asset_criticality_normal"`
	AssetCriticalityLow      int `yaml:"asset_criticality_low"`

	RecentChange int `yaml:"recent_change"`
}

// RuleEngineConfig configures Phase 11's detection rule engine
// (internal/ruleengine / internal/service/rule). The Config field/YAML
// key is "detection_rules", not "detection" — Phase 8 already claimed
// that name for DetectionConfig (finding detection); phase11.md §107's
// own worked example key ("detection:") is adapted here to avoid the
// collision.
type RuleEngineConfig struct {
	Enabled bool `yaml:"enabled"`

	Evaluation RuleEvaluationConfig `yaml:"evaluation"`

	// SuppressionDefaultWindow is the default deduplication window used
	// when a suppression doesn't specify one (phase11.md §34).  <= 0
	// uses ruleengine.DefaultSuppressionWindow.
	SuppressionDefaultWindow time.Duration `yaml:"suppression_default_window"`

	Historical RuleHistoricalConfig `yaml:"historical"`
}

// RuleEvaluationConfig bounds how one Evaluate call may run
// (phase11.md §89/§107/§108 — safe defaults, never unbounded).
type RuleEvaluationConfig struct {
	MaxConcurrency int           `yaml:"max_concurrency"`
	Timeout        time.Duration `yaml:"timeout"`
	// ClockSkew bounds how late an event may arrive relative to its
	// evaluation window before it's treated as needing re-evaluation
	// (phase11.md §46).
	ClockSkew time.Duration `yaml:"clock_skew"`
}

// RuleHistoricalConfig bounds historical (backfill-style) evaluation
// (phase11.md §57/§58/§108) — never unlimited without explicit opt-in.
type RuleHistoricalConfig struct {
	MaxRange time.Duration `yaml:"max_range"`
}

// CorrelationConfig configures Phase 12's correlation engine
// (internal/correlation / internal/service/correlation). Safe, bounded
// defaults throughout (phase12.md §110/§111) — never unlimited.
type CorrelationConfig struct {
	Enabled bool `yaml:"enabled"`

	Temporal CorrelationTemporalConfig `yaml:"temporal"`
	Graph    CorrelationGraphConfig    `yaml:"graph"`
	Workers  CorrelationWorkersConfig  `yaml:"workers"`

	// HistoricalMaxRange bounds one `ai-recon correlation evaluate`
	// call's [--from, --to) range (phase12.md §64/§110) — mirrors
	// RuleHistoricalConfig.MaxRange's identical purpose for Phase 11.
	HistoricalMaxRange time.Duration `yaml:"historical_max_range"`
	// MaxCandidates bounds how many observations one evaluation considers
	// before candidate selection truncates (phase12.md §65).
	MaxCandidates int `yaml:"max_candidates"`
}

// CorrelationTemporalConfig configures TemporalStrategy's proximity
// window (phase12.md §12).
type CorrelationTemporalConfig struct {
	DefaultWindow time.Duration `yaml:"default_window"`
}

// CorrelationGraphConfig bounds one correlation's graph size/depth
// (phase12.md §62/§63).
type CorrelationGraphConfig struct {
	MaxDepth int `yaml:"max_depth"`
	MaxNodes int `yaml:"max_nodes"`
	MaxEdges int `yaml:"max_edges"`
}

// CorrelationWorkersConfig bounds evaluation concurrency. This platform
// has no job/worker queue yet (see cmd/worker's own doc comment) — this
// value is read by ai-recon's CLI-driven evaluation for a future worker
// pool but does not yet dispatch background jobs of its own (documented
// as a Known Limitation, not fabricated infrastructure).
type CorrelationWorkersConfig struct {
	MaxConcurrency int `yaml:"max_concurrency"`
}

// AIConfig configures Phase 13's AI-assisted investigation copilot
// (internal/ai / internal/service/ai). Disabled by default (phase13.md
// §85: "AI should be explicitly enabled for production use") — an
// operator opts in explicitly, and even then defaults to the "mock"
// provider that requires no external dependency (phase13.md §88's "the
// application must remain usable without an external AI provider").
type AIConfig struct {
	Enabled bool `yaml:"enabled"`

	Provider  AIProviderConfig  `yaml:"provider"`
	Limits    AILimitsConfig    `yaml:"limits"`
	Timeouts  AITimeoutsConfig  `yaml:"timeouts"`
	Retries   AIRetriesConfig   `yaml:"retries"`
	RateLimit AIRateLimitConfig `yaml:"rate_limit"`
}

// AIProviderConfig configures which internal/ai.Provider is used and how
// (phase13.md §4). APIKeyEnv names an environment variable — the key
// itself is never accepted here (phase13.md §5).
type AIProviderConfig struct {
	Name        string  `yaml:"name"`
	Model       string  `yaml:"model"`
	Endpoint    string  `yaml:"endpoint"`
	APIKeyEnv   string  `yaml:"api_key_env"`
	MaxTokens   int     `yaml:"max_tokens"`
	Temperature float64 `yaml:"temperature"`
}

// AILimitsConfig bounds context size (phase13.md §13).
type AILimitsConfig struct {
	MaxFactsPerType int `yaml:"max_context_facts_per_type"`
	MaxTotalFacts   int `yaml:"max_context_facts"`
	MaxOutputTokens int `yaml:"max_output_tokens"`
}

// AITimeoutsConfig bounds request/tool durations (phase13.md §56).
type AITimeoutsConfig struct {
	Request time.Duration `yaml:"request"`
	Tool    time.Duration `yaml:"tool"`
}

// AIRetriesConfig bounds provider retry behavior (phase13.md §57).
type AIRetriesConfig struct {
	Max     int           `yaml:"max"`
	Backoff time.Duration `yaml:"backoff"`
}

// AIRateLimitConfig bounds AI request volume (phase13.md §55/§112) — a
// process-local limiter (see internal/service/ai.RateLimitConfig's own
// doc comment on why: no shared cache/queue infrastructure exists yet).
type AIRateLimitConfig struct {
	PerUserPerMinute   int `yaml:"per_user_per_minute"`
	PerTargetPerMinute int `yaml:"per_target_per_minute"`
	MaxConcurrent      int `yaml:"max_concurrent"`
}

// SecurityConfig enforces the platform's authorization/safety boundary
// (see work.md §2). RequireAuthorization and DryRun are read by later
// phases' scanning subsystems; Phase 1 only carries the settings through
// configuration and validation.
type SecurityConfig struct {
	RequireAuthorization bool `yaml:"require_authorization"`
	DryRun               bool `yaml:"dry_run"`
}

// validateFingerprintThresholds mirrors internal/fingerprint.Thresholds.
// Validate's exact rule, kept as a local, dependency-free copy rather
// than importing the engine package here — the same "config.go never
// imports an engine package, only mirrors its shape" boundary
// discovery.DNSDiscoveryConfig/NetworkDiscoveryConfig already establish
// relative to internal/discovery/{dns,network}.
func validateFingerprintThresholds(t Thresholds) error {
	if t == (Thresholds{}) {
		return nil // zero value means "use engine defaults"
	}
	if !(0 <= t.Low && t.Low < t.Medium && t.Medium < t.High && t.High < t.VeryHigh && t.VeryHigh <= 1) {
		return fmt.Errorf("must satisfy 0 <= low < medium < high < very_high <= 1 (got low=%v medium=%v high=%v very_high=%v)",
			t.Low, t.Medium, t.High, t.VeryHigh)
	}
	return nil
}

var validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
var validLogFormats = map[string]bool{"json": true, "text": true}
var validSSLModes = map[string]bool{"disable": true, "require": true, "verify-ca": true, "verify-full": true, "prefer": true, "allow": true}
var validEnvironments = map[string]bool{"development": true, "staging": true, "production": true, "test": true}

// validDNSRecordTypes are the forward-query record types
// discovery.dns.record_types (and profile record_types) may name. PTR is
// deliberately excluded — it's a reverse (IP -> name) lookup controlled by
// discovery.dns.reverse_ptr, not a type to query for a domain name.
var validDNSRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true,
	"NS": true, "TXT": true, "SOA": true, "CAA": true,
}

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

	if c.Discovery.DNS.Enabled {
		d := c.Discovery.DNS
		if d.Timeout <= 0 {
			errs = append(errs, "discovery.dns.timeout must be positive")
		}
		if d.MaxConcurrency < 1 {
			errs = append(errs, "discovery.dns.max_concurrency must be at least 1")
		}
		if d.RequestsPerSecond < 0 {
			errs = append(errs, "discovery.dns.requests_per_second must not be negative")
		}
		for _, addr := range d.Resolvers {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				errs = append(errs, fmt.Sprintf("discovery.dns.resolvers: %q must be a host:port pair", addr))
			}
		}
		validateRecordTypes := func(field string, types []string) {
			if len(types) == 0 {
				errs = append(errs, field+" must not be empty")
			}
			for _, rt := range types {
				if !validDNSRecordTypes[rt] {
					errs = append(errs, fmt.Sprintf("%s: %q is not a recognized (forward-query) record type", field, rt))
				}
			}
		}
		validateRecordTypes("discovery.dns.record_types", d.RecordTypes)

		if d.Subdomains.Enabled {
			s := d.Subdomains
			if s.MaxCandidates < 1 {
				errs = append(errs, "discovery.dns.subdomains.max_candidates must be at least 1")
			}
			if s.MaxDepth < 1 {
				errs = append(errs, "discovery.dns.subdomains.max_depth must be at least 1")
			}
		}
		for name, profile := range d.Profiles {
			validateRecordTypes(fmt.Sprintf("discovery.dns.profiles.%s.record_types", name), profile.RecordTypes)
		}
	}

	if c.Discovery.Endpoint.Enabled {
		ep := c.Discovery.Endpoint
		if ep.Timeout <= 0 {
			errs = append(errs, "discovery.endpoint.timeout must be positive")
		}
		if ep.MaxConcurrency < 1 {
			errs = append(errs, "discovery.endpoint.max_concurrency must be at least 1")
		}
		if ep.RequestsPerSecond < 0 {
			errs = append(errs, "discovery.endpoint.requests_per_second must not be negative")
		}
		if ep.MaxDepth < 0 {
			errs = append(errs, "discovery.endpoint.max_depth must not be negative")
		}
		if ep.MaxPages < 1 {
			errs = append(errs, "discovery.endpoint.max_pages must be at least 1")
		}
		if ep.MaxEndpoints < 1 {
			errs = append(errs, "discovery.endpoint.max_endpoints must be at least 1")
		}
		if ep.MaxResponseSize < 1 {
			errs = append(errs, "discovery.endpoint.max_response_size must be at least 1")
		}
		if ep.EnableSitemap {
			if ep.MaxSitemaps < 1 {
				errs = append(errs, "discovery.endpoint.max_sitemaps must be at least 1 when sitemap discovery is enabled")
			}
			if ep.MaxSitemapURLs < 1 {
				errs = append(errs, "discovery.endpoint.max_sitemap_urls must be at least 1 when sitemap discovery is enabled")
			}
		}
		for name, profile := range ep.Profiles {
			if profile.MaxDepth < 0 {
				errs = append(errs, fmt.Sprintf("discovery.endpoint.profiles.%s.max_depth must not be negative", name))
			}
		}
	}

	if c.Fingerprint.Enabled {
		fp := c.Fingerprint
		if fp.MinConfidence < 0 || fp.MinConfidence > 1 {
			errs = append(errs, "fingerprint.min_confidence must be between 0.0 and 1.0")
		}
		if fp.ConfidenceChangeThreshold < 0 || fp.ConfidenceChangeThreshold > 1 {
			errs = append(errs, "fingerprint.confidence_change_threshold must be between 0.0 and 1.0")
		}
		if err := validateFingerprintThresholds(fp.Thresholds); err != nil {
			errs = append(errs, "fingerprint.thresholds: "+err.Error())
		}
	}

	if c.Detection.Enabled {
		det := c.Detection
		if !validDetectionModes[strings.ToLower(det.Mode)] {
			errs = append(errs, fmt.Sprintf("detection.mode %q must be one of \"\", passive, safe_active", det.Mode))
		}
		if det.Timeout < 0 {
			errs = append(errs, "detection.timeout must not be negative")
		}
		if det.MaxResponseSize < 0 {
			errs = append(errs, "detection.max_response_size must not be negative")
		}
		if det.Evidence.MaxExcerptSize < 0 {
			errs = append(errs, "detection.evidence.max_excerpt_size must not be negative")
		}
		if det.Thresholds.CertificateExpiryDays < 0 {
			errs = append(errs, "detection.thresholds.certificate_expiry_days must not be negative")
		}
	}

	if c.Investigation.Enabled && c.Investigation.Correlation.Enabled {
		corr := c.Investigation.Correlation
		if corr.Threshold < 0 || corr.Threshold > 100 {
			errs = append(errs, "investigation.correlation.threshold must be between 0 and 100")
		}
		if corr.TemporalWindow < 0 {
			errs = append(errs, "investigation.correlation.temporal_window must not be negative")
		}
	}

	if c.Intelligence.Enabled {
		intel := c.Intelligence
		if intel.ProviderTimeout < 0 {
			errs = append(errs, "intelligence.provider_timeout must not be negative")
		}
		if intel.ReputationTTL < 0 {
			errs = append(errs, "intelligence.reputation_ttl must not be negative")
		}
		if intel.VulnerabilityTTL < 0 {
			errs = append(errs, "intelligence.vulnerability_ttl must not be negative")
		}
		if intel.ThreatFeed.RequestsPerSecond < 0 {
			errs = append(errs, "intelligence.threat_feed.requests_per_second must not be negative")
		}
		if intel.ThreatFeed.MaxRetries < 0 {
			errs = append(errs, "intelligence.threat_feed.max_retries must not be negative")
		}
		if intel.External.Enabled && intel.ThreatFeed.BaseURL != "" && intel.ThreatFeed.APIKeyEnv == "" {
			errs = append(errs, "intelligence.threat_feed.api_key_env must be set when threat_feed.base_url is configured")
		}
	}

	if c.DetectionRules.Enabled {
		det := c.DetectionRules
		if det.Evaluation.MaxConcurrency < 0 {
			errs = append(errs, "detection_rules.evaluation.max_concurrency must not be negative")
		}
		if det.Evaluation.Timeout < 0 {
			errs = append(errs, "detection_rules.evaluation.timeout must not be negative")
		}
		if det.Evaluation.ClockSkew < 0 {
			errs = append(errs, "detection_rules.evaluation.clock_skew must not be negative")
		}
		if det.SuppressionDefaultWindow < 0 {
			errs = append(errs, "detection_rules.suppression_default_window must not be negative")
		}
		if det.Historical.MaxRange < 0 {
			errs = append(errs, "detection_rules.historical.max_range must not be negative")
		}
	}

	if c.Correlation.Enabled {
		corr := c.Correlation
		if corr.Temporal.DefaultWindow < 0 {
			errs = append(errs, "correlation.temporal.default_window must not be negative")
		}
		if corr.Graph.MaxDepth < 0 {
			errs = append(errs, "correlation.graph.max_depth must not be negative")
		}
		if corr.Graph.MaxNodes < 0 {
			errs = append(errs, "correlation.graph.max_nodes must not be negative")
		}
		if corr.Graph.MaxEdges < 0 {
			errs = append(errs, "correlation.graph.max_edges must not be negative")
		}
		if corr.Workers.MaxConcurrency < 0 {
			errs = append(errs, "correlation.workers.max_concurrency must not be negative")
		}
		if corr.HistoricalMaxRange < 0 {
			errs = append(errs, "correlation.historical_max_range must not be negative")
		}
		if corr.MaxCandidates < 0 {
			errs = append(errs, "correlation.max_candidates must not be negative")
		}
	}

	if c.AI.Enabled {
		aiCfg := c.AI
		if strings.TrimSpace(aiCfg.Provider.Name) == "" {
			errs = append(errs, "ai.provider.name must not be empty when ai.enabled is true")
		}
		if aiCfg.Provider.Name == "openai" && strings.TrimSpace(aiCfg.Provider.Endpoint) == "" {
			errs = append(errs, "ai.provider.endpoint must not be empty when ai.provider.name is \"openai\"")
		}
		if aiCfg.Provider.MaxTokens < 0 {
			errs = append(errs, "ai.provider.max_tokens must not be negative")
		}
		if aiCfg.Provider.Temperature < 0 || aiCfg.Provider.Temperature > 2 {
			errs = append(errs, "ai.provider.temperature must be between 0 and 2")
		}
		if aiCfg.Limits.MaxFactsPerType < 0 || aiCfg.Limits.MaxTotalFacts < 0 || aiCfg.Limits.MaxOutputTokens < 0 {
			errs = append(errs, "ai.limits values must not be negative")
		}
		if aiCfg.Timeouts.Request < 0 || aiCfg.Timeouts.Tool < 0 {
			errs = append(errs, "ai.timeouts values must not be negative")
		}
		if aiCfg.Retries.Max < 0 || aiCfg.Retries.Backoff < 0 {
			errs = append(errs, "ai.retries values must not be negative")
		}
		if aiCfg.RateLimit.PerUserPerMinute < 0 || aiCfg.RateLimit.PerTargetPerMinute < 0 || aiCfg.RateLimit.MaxConcurrent < 0 {
			errs = append(errs, "ai.rate_limit values must not be negative")
		}
	}

	if !validLogLevels[strings.ToLower(c.Logging.Level)] {
		errs = append(errs, fmt.Sprintf("logging.level %q must be one of debug, info, warn, error", c.Logging.Level))
	}
	if !validLogFormats[strings.ToLower(c.Logging.Format)] {
		errs = append(errs, fmt.Sprintf("logging.format %q must be one of json, text", c.Logging.Format))
	}

	// Production-only guard rails (phase15.md §3/§33/§107): a configuration
	// that would be perfectly valid in development must still fail fast at
	// startup if it carries an unsafe-for-production setting, rather than
	// silently running with it. These check the same fields validated
	// generically above, so they run after those checks would already have
	// caught an outright invalid value.
	if strings.EqualFold(c.Application.Environment, "production") {
		if strings.EqualFold(c.Logging.Level, "debug") {
			errs = append(errs, "logging.level must not be \"debug\" when application.environment is \"production\" (phase15.md §33)")
		}
		if !c.Security.RequireAuthorization {
			errs = append(errs, "security.require_authorization must be true when application.environment is \"production\" (see SECURITY.md)")
		}
		if c.Database.SSLMode == "disable" {
			errs = append(errs, "database.ssl_mode must not be \"disable\" when application.environment is \"production\" (see docs/operations/production-readiness.md)")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
