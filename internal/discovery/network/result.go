package network

import (
	"time"

	"github.com/google/uuid"
)

// State is the outcome of one TCP connect attempt.
type State string

// Recognized port states. TIMEOUT is reported only for an actual dial
// timeout/context deadline — never relabeled FILTERED, which would claim
// firewall semantics a bare TCP timeout cannot establish on its own
// (phase4.md §14/§20).
const (
	StateOpen    State = "OPEN"
	StateClosed  State = "CLOSED"
	StateTimeout State = "TIMEOUT"
	StateError   State = "ERROR"
)

// Service is a conservative, evidence-limited classification of what a
// service on an open port looks like. A port number alone is weak
// evidence — see classifier.go — so this is never presented as a
// confirmed identification, only a classification.
type Service string

// Recognized service classifications.
const (
	ServiceUnknown  Service = "UNKNOWN"
	ServiceHTTP     Service = "HTTP"
	ServiceHTTPS    Service = "HTTPS"
	ServiceSSH      Service = "SSH"
	ServiceFTP      Service = "FTP"
	ServiceSMTP     Service = "SMTP"
	ServiceDNS      Service = "DNS"
	ServiceDatabase Service = "DATABASE"
	ServiceTLS      Service = "TLS_SERVICE"
	ServiceOther    Service = "OTHER"
)

// TLSMetadata captures minimal, safe TLS handshake metadata for a port
// classified as (or confirmed to speak) TLS — the same restraint
// internal/httpclient.TLSMetadata applies: no certificate chains, no key
// material, just enough for later fingerprinting. Subject/Issuer are the
// certificate's CommonName only.
type TLSMetadata struct {
	Version              string
	CipherSuite          string
	PeerCertificateCount int
	Subject              string
	Issuer               string
	NotAfter             time.Time
}

// PortResult is one host:port TCP connect outcome.
type PortResult struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID

	Host     string
	Port     int
	Protocol string // always "tcp" in this phase

	State    State
	Duration time.Duration

	Service     Service
	Indicators  []string // human-readable evidence for Service/candidate flags
	TLSMetadata *TLSMetadata

	HTTPCandidate      bool
	AIServiceCandidate bool
	CandidateReason    string // e.g. "configured_ai_port" (phase4.md §24)

	ObservedAt time.Time

	// Error carries a transport-level failure description for STATE_ERROR
	// results (network unreachable, unexpected dial error, ...) — not set
	// for CLOSED (connection refused is an expected, informative outcome)
	// or TIMEOUT.
	Error string

	// Skipped is set for a generated host:port pair that was never
	// connected to because it failed scope validation. SkippedReason
	// explains why — never silently discarded (mirrors phase3.md §24's
	// discipline for HTTP discovery's blocked redirects).
	Skipped       bool
	SkippedReason string
}

// Succeeded reports whether r represents a completed connection attempt
// worth normalizing into an asset (an OPEN port) — as opposed to a
// transport failure, a non-open state, or a skipped/out-of-scope pair.
func (r PortResult) Succeeded() bool {
	return r.Error == "" && !r.Skipped && r.State == StateOpen
}

// Summary aggregates every PortResult from one network discovery run
// (phase4.md §30).
type Summary struct {
	ScanID   uuid.UUID
	TargetID uuid.UUID
	Target   string

	HostsScanned   int
	PortsAttempted int
	Open           int
	Closed         int
	Timeouts       int
	Errors         int

	HTTPCandidates int
	AICandidates   int

	Duration time.Duration

	Results []PortResult
}
