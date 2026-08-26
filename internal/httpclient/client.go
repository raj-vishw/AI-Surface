// Package httpclient is a reusable, safe-by-default HTTP transport
// abstraction. It is NOT the discovery engine — it is the transport that
// future discovery and fingerprinting subsystems will build on.
//
// It is safe by default: every Client enforces a request timeout, a
// maximum response body size (bodies are never read unbounded into
// memory), and a maximum redirect count. TLS metadata and a SHA-256 body
// hash are captured on every response for later fingerprinting use.
//
// Redirect policy for Phase 1: once MaxRedirects hops have been followed,
// the client stops following further redirects and returns the last
// response as-is (http.ErrUseLastResponse) rather than erroring — this is
// the "configurable redirect policy" required for this phase. It does not
// restrict *which* hosts a redirect may point to; that host-allowlisting
// (SSRF protection) is explicitly deferred to a later phase per the master
// specification, which asks Phase 1 only to prepare the abstraction for it.
package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"

	"ai-recon-platform/internal/config"
)

// Options configures a Client.
type Options struct {
	Timeout               time.Duration
	MaxIdleConnections    int
	MaxConnectionsPerHost int
	MaxResponseSize       int64
	MaxRedirects          int
	TLSConfig             *tls.Config
}

// OptionsFromConfig builds Options from the application's HTTPClientConfig.
func OptionsFromConfig(cfg config.HTTPClientConfig) Options {
	return Options{
		Timeout:               cfg.Timeout,
		MaxIdleConnections:    cfg.MaxIdleConnections,
		MaxConnectionsPerHost: cfg.MaxConnectionsPerHost,
		MaxResponseSize:       cfg.MaxResponseSize,
		MaxRedirects:          cfg.MaxRedirects,
	}
}

// Client is a reusable HTTP client with bounded resource usage.
type Client struct {
	httpClient      *http.Client
	maxResponseSize int64
}

// New builds a Client from opts. The underlying transport pools and reuses
// connections according to opts.MaxIdleConnections /
// opts.MaxConnectionsPerHost.
func New(opts Options) *Client {
	transport := &http.Transport{
		MaxIdleConns:        opts.MaxIdleConnections,
		MaxIdleConnsPerHost: opts.MaxConnectionsPerHost,
		MaxConnsPerHost:     opts.MaxConnectionsPerHost,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     opts.TLSConfig,
		ForceAttemptHTTP2:   true,
	}

	maxRedirects := opts.MaxRedirects

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	maxResponseSize := opts.MaxResponseSize
	if maxResponseSize <= 0 {
		maxResponseSize = 10 * 1024 * 1024 // 10 MiB fallback
	}

	return &Client{httpClient: httpClient, maxResponseSize: maxResponseSize}
}

// NewFromConfig is a convenience wrapper for New(OptionsFromConfig(cfg)).
func NewFromConfig(cfg config.HTTPClientConfig) *Client {
	return New(OptionsFromConfig(cfg))
}
