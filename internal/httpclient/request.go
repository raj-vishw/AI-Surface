package httpclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	apperrors "ai-recon-platform/internal/errors"
)

// Request describes a single HTTP request to execute.
type Request struct {
	Method  string
	URL     string
	Headers http.Header
	Body    io.Reader
}

// redirectChainKey is the context key Do attaches a per-request
// *redirectChain collector under, so the Client-wide CheckRedirect closure
// (shared by every concurrent request) can record each request's own hop
// URLs without any cross-request data race — see Client's CheckRedirect
// and Response.RedirectChain.
type redirectChainKey struct{}

// redirectChain accumulates the URL of every hop CheckRedirect is invoked
// for during one logical request (net/http propagates the original
// request's context to every redirected request, which is what makes this
// safe to key off context rather than the Client itself).
type redirectChain struct {
	hops []string
}

// Do executes req and returns a normalized Response. It respects ctx
// cancellation/deadlines, the Client's configured timeout, redirect limit,
// and maximum response size — the response body is never read unbounded
// into memory.
//
// Do only returns an error for transport-level failures (DNS, connection
// refused, timeout, context cancellation, oversized body). Non-2xx HTTP
// status codes are not errors — they are returned as a normal Response
// with StatusCode set, exactly as net/http behaves.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	collector := &redirectChain{}
	ctx = context.WithValue(ctx, redirectChainKey{}, collector)

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, req.Body)
	if err != nil {
		return nil, apperrors.NewValidation(fmt.Sprintf("building %s request to %s", req.Method, req.URL), err)
	}
	for key, values := range req.Headers {
		for _, v := range values {
			httpReq.Header.Add(key, v)
		}
	}

	start := time.Now()
	httpResp, err := c.httpClient.Do(httpReq)
	duration := time.Since(start)
	if err != nil {
		return nil, apperrors.NewNetwork(fmt.Sprintf("requesting %s %s", req.Method, req.URL), err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Read at most maxResponseSize+1 bytes so we can detect an oversized
	// body without ever buffering more than that in memory.
	limited := io.LimitReader(httpResp.Body, c.maxResponseSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, apperrors.NewNetwork("reading response body", err)
	}
	if int64(len(data)) > c.maxResponseSize {
		return nil, apperrors.NewValidation(
			fmt.Sprintf("response body exceeds maximum size of %d bytes", c.maxResponseSize), nil,
		)
	}

	sum := sha256.Sum256(data)

	respURL := req.URL
	if httpResp.Request != nil && httpResp.Request.URL != nil {
		respURL = httpResp.Request.URL.String()
	}

	return &Response{
		StatusCode:    httpResp.StatusCode,
		Headers:       httpResp.Header,
		ContentType:   httpResp.Header.Get("Content-Type"),
		Body:          data,
		BodySize:      int64(len(data)),
		Duration:      duration,
		URL:           respURL,
		TLSMetadata:   extractTLSMetadata(httpResp.TLS),
		BodySHA256:    hex.EncodeToString(sum[:]),
		RedirectChain: collector.hops,
	}, nil
}

// Get issues a GET request.
func (c *Client) Get(ctx context.Context, url string, headers http.Header) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodGet, URL: url, Headers: headers})
}

// Post issues a POST request with body.
func (c *Client) Post(ctx context.Context, url string, body io.Reader, headers http.Header) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodPost, URL: url, Body: body, Headers: headers})
}

// Put issues a PUT request with body.
func (c *Client) Put(ctx context.Context, url string, body io.Reader, headers http.Header) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodPut, URL: url, Body: body, Headers: headers})
}

// Patch issues a PATCH request with body.
func (c *Client) Patch(ctx context.Context, url string, body io.Reader, headers http.Header) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodPatch, URL: url, Body: body, Headers: headers})
}

// Delete issues a DELETE request.
func (c *Client) Delete(ctx context.Context, url string, headers http.Header) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodDelete, URL: url, Headers: headers})
}

// Head issues a HEAD request.
func (c *Client) Head(ctx context.Context, url string, headers http.Header) (*Response, error) {
	return c.Do(ctx, Request{Method: http.MethodHead, URL: url, Headers: headers})
}
