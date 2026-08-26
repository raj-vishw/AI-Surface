package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// TLSMetadata captures minimal, non-sensitive information about the TLS
// connection a response was received over. It intentionally does not
// retain full certificate chains — just enough for later fingerprinting
// (negotiated version/cipher, how many certificates the peer presented).
type TLSMetadata struct {
	Version              string
	CipherSuite          string
	PeerCertificateCount int
}

// Response is the platform's normalized HTTP response model. Body is
// bounded by the Client's configured maximum response size — it is never
// an unbounded read of the wire.
type Response struct {
	StatusCode  int
	Headers     http.Header
	ContentType string
	Body        []byte
	BodySize    int64
	Duration    time.Duration
	URL         string
	TLSMetadata *TLSMetadata
	// BodySHA256 is the hex-encoded SHA-256 hash of Body, used by later
	// asset/fingerprint components to detect identical responses.
	BodySHA256 string
}

func extractTLSMetadata(state *tls.ConnectionState) *TLSMetadata {
	if state == nil {
		return nil
	}
	return &TLSMetadata{
		Version:              tlsVersionName(state.Version),
		CipherSuite:          tls.CipherSuiteName(state.CipherSuite),
		PeerCertificateCount: len(state.PeerCertificates),
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
