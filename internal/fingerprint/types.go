// Package fingerprint implements the passive technology-fingerprinting
// engine (Phase 6): declarative signatures, deterministic signal
// matching, transparent confidence scoring, and technology normalization.
// It analyzes an already-built Observation (see evidence.go) — assembled
// by internal/service/fingerprint from data Phase 3/4/5 already
// collected — and never performs network I/O of its own (phase6.md §46).
//
// This package has no dependency on internal/domain/fingerprint or any
// database/repository code, the same "engine is self-contained, the
// service layer bridges it to persistence" split
// internal/discovery/{http,network,dns} already establish relative to
// internal/domain/asset.
package fingerprint

import "fmt"

// Category mirrors internal/domain/fingerprint.Category's string
// vocabulary exactly (kept as a distinct Go type per this package's
// no-domain-dependency rule — see the package doc comment). Signature
// files declare a category using these same string values.
type Category string

// Recognized fingerprint categories (phase6.md §4) — identical vocabulary
// to internal/domain/fingerprint.Category.
const (
	CategoryWebServer        Category = "web_server"
	CategoryReverseProxy     Category = "reverse_proxy"
	CategoryFramework        Category = "framework"
	CategoryFrontend         Category = "frontend"
	CategoryRuntime          Category = "runtime"
	CategoryProgrammingLang  Category = "programming_language"
	CategoryCMS              Category = "cms"
	CategoryAPI              Category = "api"
	CategoryCloud            Category = "cloud"
	CategoryCDN              Category = "cdn"
	CategoryDatabase         Category = "database"
	CategoryAuthentication   Category = "authentication"
	CategoryMonitoring       Category = "monitoring"
	CategoryAnalytics        Category = "analytics"
	CategoryAIProvider       Category = "ai_provider"
	CategoryAIPlatform       Category = "ai_platform"
	CategoryAIModelCandidate Category = "ai_model_candidate"
	CategoryService          Category = "service"
	CategoryLibrary          Category = "library"
	CategoryInfrastructure   Category = "infrastructure"
)

var validCategories = map[Category]bool{
	CategoryWebServer: true, CategoryReverseProxy: true, CategoryFramework: true,
	CategoryFrontend: true, CategoryRuntime: true, CategoryProgrammingLang: true,
	CategoryCMS: true, CategoryAPI: true, CategoryCloud: true, CategoryCDN: true,
	CategoryDatabase: true, CategoryAuthentication: true, CategoryMonitoring: true,
	CategoryAnalytics: true, CategoryAIProvider: true, CategoryAIPlatform: true,
	CategoryAIModelCandidate: true, CategoryService: true, CategoryLibrary: true,
	CategoryInfrastructure: true,
}

// Valid reports whether c is a recognized category.
func (c Category) Valid() bool { return validCategories[c] }

// SignalType identifies what kind of observation a SignalRule inspects
// (phase6.md §6). "response_header" is accepted as a synonym of
// "http_header" — both inspect the same Observation.Headers map — purely
// so a signature author can use whichever reads more naturally; the
// matcher treats them identically.
type SignalType string

// Recognized signal types (phase6.md §6).
const (
	SignalHTTPHeader      SignalType = "http_header"
	SignalResponseHeader  SignalType = "response_header" // synonym of SignalHTTPHeader
	SignalContentType     SignalType = "content_type"
	SignalHTML            SignalType = "html"
	SignalHTMLMeta        SignalType = "html_meta"
	SignalScript          SignalType = "script"
	SignalStylesheet      SignalType = "stylesheet"
	SignalCookieName      SignalType = "cookie_name"
	SignalURLPath         SignalType = "url_path"
	SignalAPIPath         SignalType = "api_path"
	SignalJSONStructure   SignalType = "json_structure"
	SignalErrorMessage    SignalType = "error_message"
	SignalDNSCNAME        SignalType = "dns_cname"
	SignalDNSRecord       SignalType = "dns_record"
	SignalService         SignalType = "service"
	SignalPort            SignalType = "port"
	SignalTLS             SignalType = "tls"
	SignalResponseHash    SignalType = "response_hash"
	SignalRateLimitHeader SignalType = "rate_limit_header"
)

var validSignalTypes = map[SignalType]bool{
	SignalHTTPHeader: true, SignalResponseHeader: true, SignalContentType: true,
	SignalHTML: true, SignalHTMLMeta: true, SignalScript: true, SignalStylesheet: true,
	SignalCookieName: true, SignalURLPath: true, SignalAPIPath: true,
	SignalJSONStructure: true, SignalErrorMessage: true, SignalDNSCNAME: true,
	SignalDNSRecord: true, SignalService: true, SignalPort: true, SignalTLS: true,
	SignalResponseHash: true, SignalRateLimitHeader: true,
}

// Valid reports whether t is a recognized signal type.
func (t SignalType) Valid() bool { return validSignalTypes[t] }

// Level names a bucketed confidence Score — identical vocabulary to
// internal/domain/fingerprint.Level (phase6.md §8).
type Level string

// Recognized levels, weak to very_high.
const (
	LevelWeak     Level = "weak"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelVeryHigh Level = "very_high"
)

// Thresholds are the configurable confidence-level boundaries (phase6.md
// §8: "these thresholds should be configurable rather than hardcoded
// where practical"). Each field is the minimum score (inclusive) for that
// level; DefaultThresholds matches the spec's own worked example exactly.
type Thresholds struct {
	Low      float64
	Medium   float64
	High     float64
	VeryHigh float64
}

// DefaultThresholds is the spec's own worked example: 0.00-0.29 weak,
// 0.30-0.59 low, 0.60-0.79 medium, 0.80-0.94 high, 0.95-1.00 very_high.
var DefaultThresholds = Thresholds{Low: 0.30, Medium: 0.60, High: 0.80, VeryHigh: 0.95}

// Level buckets score using t (or DefaultThresholds if t is the zero
// value).
func (t Thresholds) Level(score float64) Level {
	if t == (Thresholds{}) {
		t = DefaultThresholds
	}
	switch {
	case score >= t.VeryHigh:
		return LevelVeryHigh
	case score >= t.High:
		return LevelHigh
	case score >= t.Medium:
		return LevelMedium
	case score >= t.Low:
		return LevelLow
	default:
		return LevelWeak
	}
}

// Validate reports whether t's boundaries are sane (strictly increasing,
// within [0,1]) — called when loading fingerprint configuration, never
// silently tolerated as a misconfiguration (phase6.md §28's "fail
// clearly" principle applied to thresholds too).
func (t Thresholds) Validate() error {
	if t == (Thresholds{}) {
		return nil // zero value means "use defaults" — always valid
	}
	if !(0 <= t.Low && t.Low < t.Medium && t.Medium < t.High && t.High < t.VeryHigh && t.VeryHigh <= 1) {
		return fmt.Errorf("fingerprint thresholds must satisfy 0 <= low < medium < high < very_high <= 1 (got low=%v medium=%v high=%v very_high=%v)",
			t.Low, t.Medium, t.High, t.VeryHigh)
	}
	return nil
}
