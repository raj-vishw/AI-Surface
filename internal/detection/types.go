// Package detection implements Phase 8's finding/vulnerability detection
// engine: a self-contained set of Detectors that analyze evidence Phase
// 2-7 already collected and persisted, and turn it into normalized,
// explainable Finding values. Mirroring internal/fingerprint's split
// (phase6.md §47), this package has no dependency on
// internal/domain/finding or any database/repository package — it takes
// an in-memory Input built entirely from already-persisted data and
// returns in-memory Finding values; internal/service/detection is the
// bridge that assembles Input, calls Engine.Evaluate, and persists the
// result (phase8.md §1).
//
// Detection defaults to passive analysis: reading headers, TLS metadata,
// cookie attributes, classification, and technology fingerprints Phase
// 2-7 already stored — no network request of its own. A small, explicitly
// enabled safe-active mode (phase8.md §14/§54) allows a detector to issue
// exactly one bounded, scope-checked request against an already-known URL
// (never a newly-guessed path, never a brute-force wordlist) via
// SafeActiveFetcher; see safeactive.go.
package detection

import (
	"time"

	"github.com/google/uuid"
)

// Mode selects how aggressively one detection run may act.
type Mode string

// Recognized detection modes (phase8.md §54). Passive is the default.
const (
	ModePassive    Mode = "passive"
	ModeSafeActive Mode = "safe_active"
)

// Valid reports whether m is a recognized mode.
func (m Mode) Valid() bool { return m == ModePassive || m == ModeSafeActive }

// AssetObservation is the normalized slice of an already-persisted Asset
// (internal/domain/asset) a detector needs. Metadata is the asset's
// already-sanitized Metadata map — headers, tls_version/tls_cipher_suite,
// cookie_names, cookies (attribute-only, see cookies.go), server, and
// indicators, exactly as Phase 3/6/7 persisted it.
type AssetObservation struct {
	ID         uuid.UUID
	TargetID   uuid.UUID
	Type       string
	Hostname   string
	IP         string
	URL        string
	Scheme     string
	Host       string
	Port       int
	Confidence float64
	Metadata   map[string]any
	FirstSeen  time.Time
	LastSeen   time.Time
}

// EndpointObservation is the normalized slice of an already-persisted
// Endpoint (internal/domain/endpoint, Phase 7) belonging to the Asset
// under analysis. Metadata carries the same per-response shape
// AssetObservation.Metadata does (Phase 3's buildMetadata is written to
// both the asset and its endpoint — see internal/discovery/service/
// discovery.go), so header/cookie/CORS detectors can analyze it exactly
// as observed at this specific URL, not just the asset's most recent
// response.
type EndpointObservation struct {
	ID             uuid.UUID
	AssetID        uuid.UUID
	URL            string
	Method         string
	Path           string
	StatusCode     int
	ContentType    string
	Classification string
	APIType        string
	APIVersion     string
	Documented     bool
	Observed       bool
	Inferred       bool
	Metadata       map[string]any
	// Parameters lists observed parameter *names* only (phase7.md §9) —
	// never a value.
	Parameters []string
}

// TLSObservation is TLS/certificate metadata Phase 4's network scanner
// already captured for a host:port sibling of Asset (persisted as a
// PORT/SERVICE asset's metadata — see internal/discovery/service/
// network.go's buildNetworkMetadata) — kept distinct from
// AssetObservation.Metadata's own tls_version/tls_cipher_suite fields
// (captured by Phase 3's HTTP client at the response layer, with no
// certificate detail) because only Phase 4's raw TCP+TLS probe observes
// certificate Subject/Issuer/NotAfter.
type TLSObservation struct {
	Host        string
	Port        int
	Version     string
	CipherSuite string
	Subject     string
	Issuer      string
	// NotAfter is the certificate's expiry, or the zero time if Phase 4
	// never captured one (an older observation, or a handshake that
	// completed without exposing a leaf certificate).
	NotAfter time.Time
}

// ServiceObservation is one already-persisted Phase 4 PORT/SERVICE asset
// observation for a host sibling of Asset (internal/discovery/network,
// persisted via internal/discovery/service/network.go's
// buildNetworkMetadata) — a plain TCP-connect-level fact ("port 5432 is
// open and looks like a database"), never itself a vulnerability claim.
type ServiceObservation struct {
	Host     string
	Port     int
	Protocol string
	State    string // "OPEN", "CLOSED", "FILTERED", "TIMEOUT", "ERROR"
	Service  string // "HTTP", "HTTPS", "SSH", "DATABASE", "TLS_SERVICE", "UNKNOWN"
}

// FingerprintObservation is one already-persisted technology belief
// (internal/domain/fingerprint, Phase 6) for the Asset under analysis.
type FingerprintObservation struct {
	Category   string
	Technology string
	Vendor     string
	Version    string
	Confidence float64
}

// Input bundles everything one detection pass over a single asset
// consumes. Built entirely from already-persisted Phase 2-7 data by
// internal/service/detection — never assembled by a Detector itself
// (phase8.md §1/§53).
type Input struct {
	Asset        AssetObservation
	Endpoints    []EndpointObservation
	TLS          []TLSObservation
	Services     []ServiceObservation
	Fingerprints []FingerprintObservation

	Mode    Mode
	Fetcher SafeActiveFetcher // nil unless Mode == ModeSafeActive

	Config Config
}
