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

func TestValidateRejectsInvalidNetworkConnectTimeout(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Network.Enabled = true
	cfg.Discovery.Network.ConnectTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero connect_timeout")
	}
}

func TestValidateRejectsInvalidNetworkConcurrency(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Network.Enabled = true
	cfg.Discovery.Network.MaxConcurrency = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero max_concurrency")
	}
}

func TestValidateRejectsInvalidNetworkMaxHosts(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Network.Enabled = true
	cfg.Discovery.Network.MaxHosts = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero max_hosts")
	}
}

func TestValidateRejectsNegativeNetworkRate(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Network.Enabled = true
	cfg.Discovery.Network.RequestsPerSecond = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative requests_per_second")
	}
}

func TestValidateRejectsInvalidNetworkCandidatePort(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Network.Enabled = true
	cfg.Discovery.Network.AICandidatePorts = []int{70000}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for an out-of-range candidate port")
	}
}

func TestValidateRejectsInvalidNetworkProfile(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Network.Enabled = true
	cfg.Discovery.Network.Profiles["broken"] = NetworkProfileConfig{Ports: nil}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for a profile with no ports")
	}
}

func TestValidateAllowsNetworkDiscoveryDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Network.Enabled = false
	cfg.Discovery.Network.MaxConcurrency = -1 // would be invalid if enabled
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled network discovery should skip its own validation, got: %v", err)
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

func TestValidateRejectsInvalidDNSTimeout(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.dns.timeout")
	}
}

func TestValidateRejectsInvalidDNSConcurrency(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.MaxConcurrency = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.dns.max_concurrency")
	}
}

func TestValidateRejectsNegativeDNSRate(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.RequestsPerSecond = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative discovery.dns.requests_per_second")
	}
}

func TestValidateRejectsInvalidDNSResolverAddress(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.Resolvers = []string{"not-a-host-port"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for a malformed discovery.dns.resolvers entry")
	}
}

func TestValidateRejectsInvalidDNSRecordType(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.RecordTypes = []string{"BOGUS"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for an unrecognized discovery.dns.record_types entry")
	}
}

func TestValidateRejectsPTRAsForwardRecordType(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.RecordTypes = []string{"PTR"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error: PTR is reverse-only, not valid in record_types")
	}
}

func TestValidateRejectsEmptyDNSRecordTypes(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.RecordTypes = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty discovery.dns.record_types")
	}
}

func TestValidateRejectsInvalidDNSMaxCandidates(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.Subdomains.Enabled = true
	cfg.Discovery.DNS.Subdomains.MaxCandidates = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.dns.subdomains.max_candidates")
	}
}

func TestValidateRejectsInvalidDNSMaxDepth(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.Subdomains.Enabled = true
	cfg.Discovery.DNS.Subdomains.MaxDepth = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.dns.subdomains.max_depth")
	}
}

func TestValidateAllowsDNSSubdomainsDisabledSkipsTheirValidation(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.Subdomains.Enabled = false
	cfg.Discovery.DNS.Subdomains.MaxCandidates = 0 // would be invalid if subdomains were enabled
	cfg.Discovery.DNS.Subdomains.MaxDepth = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled DNS subdomain enumeration should skip its own validation, got: %v", err)
	}
}

func TestValidateRejectsInvalidDNSProfileRecordType(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = true
	cfg.Discovery.DNS.Profiles["broken"] = DNSProfileConfig{RecordTypes: []string{"BOGUS"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for an unrecognized record type in a discovery.dns.profiles entry")
	}
}

func TestValidateAllowsDNSDiscoveryDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.DNS.Enabled = false
	cfg.Discovery.DNS.MaxConcurrency = -1 // would be invalid if enabled
	cfg.Discovery.DNS.RecordTypes = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled DNS discovery should skip its own validation, got: %v", err)
	}
}

func TestValidateRejectsInvalidEndpointTimeout(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.endpoint.timeout")
	}
}

func TestValidateRejectsInvalidEndpointConcurrency(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.MaxConcurrency = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.endpoint.max_concurrency")
	}
}

func TestValidateRejectsNegativeEndpointRate(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.RequestsPerSecond = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative discovery.endpoint.requests_per_second")
	}
}

func TestValidateRejectsNegativeEndpointMaxDepth(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.MaxDepth = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative discovery.endpoint.max_depth")
	}
}

func TestValidateRejectsInvalidEndpointMaxPages(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.MaxPages = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.endpoint.max_pages")
	}
}

func TestValidateRejectsInvalidEndpointMaxEndpoints(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.MaxEndpoints = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.endpoint.max_endpoints")
	}
}

func TestValidateRejectsInvalidEndpointMaxResponseSize(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.MaxResponseSize = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero discovery.endpoint.max_response_size")
	}
}

func TestValidateRejectsInvalidSitemapLimitsWhenEnabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.EnableSitemap = true
	cfg.Discovery.Endpoint.MaxSitemaps = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for zero max_sitemaps when sitemap discovery is enabled")
	}
}

func TestValidateAllowsSitemapLimitsWhenDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = true
	cfg.Discovery.Endpoint.EnableSitemap = false
	cfg.Discovery.Endpoint.MaxSitemaps = 0
	cfg.Discovery.Endpoint.MaxSitemapURLs = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled sitemap discovery should skip its own limit validation, got: %v", err)
	}
}

func TestValidateAllowsEndpointDiscoveryDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Discovery.Endpoint.Enabled = false
	cfg.Discovery.Endpoint.MaxConcurrency = -1 // would be invalid if enabled
	cfg.Discovery.Endpoint.MaxPages = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled endpoint discovery should skip its own validation, got: %v", err)
	}
}

func TestValidateRejectsInvalidDetectionMode(t *testing.T) {
	cfg := defaultConfig()
	cfg.Detection.Enabled = true
	cfg.Detection.Mode = "aggressive"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid detection.mode")
	}
}

func TestValidateAllowsEmptyDetectionMode(t *testing.T) {
	cfg := defaultConfig()
	cfg.Detection.Enabled = true
	cfg.Detection.Mode = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected empty detection.mode (defaults to passive) to be valid, got: %v", err)
	}
}

func TestValidateRejectsNegativeDetectionTimeout(t *testing.T) {
	cfg := defaultConfig()
	cfg.Detection.Enabled = true
	cfg.Detection.Timeout = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative detection.timeout")
	}
}

func TestValidateRejectsNegativeDetectionMaxExcerptSize(t *testing.T) {
	cfg := defaultConfig()
	cfg.Detection.Enabled = true
	cfg.Detection.Evidence.MaxExcerptSize = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative detection.evidence.max_excerpt_size")
	}
}

func TestValidateRejectsNegativeCertificateExpiryDays(t *testing.T) {
	cfg := defaultConfig()
	cfg.Detection.Enabled = true
	cfg.Detection.Thresholds.CertificateExpiryDays = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative detection.thresholds.certificate_expiry_days")
	}
}

func TestValidateAllowsDetectionDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Detection.Enabled = false
	cfg.Detection.Mode = "not-a-real-mode" // would be invalid if enabled
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled detection should skip its own validation, got: %v", err)
	}
}
