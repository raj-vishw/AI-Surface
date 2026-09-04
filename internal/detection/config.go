package detection

import "time"

// DefaultMaxExcerptLength bounds a safe-active evidence excerpt when
// Config.MaxExcerptLength is unset (phase8.md §9/§27/§56).
const DefaultMaxExcerptLength = 2048

// DefaultCertificateExpiryWarnDays is the "expires soon" threshold
// (phase8.md §25/§56) used when Config.CertificateExpiryWarnDays is unset.
const DefaultCertificateExpiryWarnDays = 14

// DefaultRequestTimeout bounds one safe-active request when
// Config.RequestTimeout is unset.
const DefaultRequestTimeout = 10 * time.Second

// DefaultMaxResponseSize bounds one safe-active response body when
// Config.MaxResponseSize is unset — deliberately small: safe-active
// detectors only ever need a short excerpt, never a full page
// (phase8.md §27/§29).
const DefaultMaxResponseSize int64 = 262144

// Config configures one Engine.Evaluate run. It carries no database or
// scope-construction detail — internal/service/detection resolves those
// and passes only the bounds a Detector actually needs.
type Config struct {
	// Detectors maps a detector id to whether it is enabled. A detector
	// absent from the map is enabled by default (phase8.md §6 — "support
	// enabled/disabled detectors" without requiring recompilation or an
	// exhaustive allowlist).
	Detectors map[string]bool

	// MaxExcerptLength bounds any sanitized response excerpt a safe-active
	// detector records as evidence (phase8.md §27's "strict maximum
	// length"). <= 0 uses DefaultMaxExcerptLength.
	MaxExcerptLength int
	// CertificateExpiryWarnDays is the "expires soon" threshold
	// (phase8.md §25). <= 0 uses DefaultCertificateExpiryWarnDays.
	CertificateExpiryWarnDays int

	// RequestTimeout/MaxResponseSize bound every safe-active request a
	// detector issues via Input.Fetcher. <= 0 uses the package defaults.
	RequestTimeout  time.Duration
	MaxResponseSize int64
}

// ExcerptLimit returns c's effective MaxExcerptLength.
func (c Config) ExcerptLimit() int {
	if c.MaxExcerptLength <= 0 {
		return DefaultMaxExcerptLength
	}
	return c.MaxExcerptLength
}

// ExpiryWarnDays returns c's effective CertificateExpiryWarnDays.
func (c Config) ExpiryWarnDays() int {
	if c.CertificateExpiryWarnDays <= 0 {
		return DefaultCertificateExpiryWarnDays
	}
	return c.CertificateExpiryWarnDays
}

// DetectorEnabled reports whether id is enabled under c — absent means
// enabled (see Detectors' doc comment).
func (c Config) DetectorEnabled(id string) bool {
	if c.Detectors == nil {
		return true
	}
	enabled, ok := c.Detectors[id]
	if !ok {
		return true
	}
	return enabled
}
