package detection

import "context"

// FetchResult is the bounded outcome of one SafeActiveFetcher.Fetch call.
// Body is capped by the caller-supplied maxBytes — a detector must reduce
// it to a short sanitized excerpt via TruncateExcerpt (see evidence.go)
// before ever attaching it as Evidence, and must never retain the full
// Body itself (phase8.md §9/§27/§29).
type FetchResult struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

// SafeActiveFetcher performs one bounded, scope-checked, already-
// authorized GET request. Detectors never construct their own HTTP
// transport or scope check — internal/service/detection builds the one
// implementation of this interface (backed by internal/httpclient.Client,
// reusing the same Phase 1 client and Phase 3 ScopeValidator every other
// discovery engine uses — phase8.md §1's "do not create duplicate HTTP
// clients / scope validators") and hands it to Engine.Evaluate only when
// Mode is ModeSafeActive.
//
// A Detector must only ever call Fetch with a URL that is either (a)
// already present in Input (an observed/documented endpoint) or (b) one
// of a small, fixed, well-known path list it declares in its own source
// (e.g. "/robots.txt", "/.well-known/security.txt") — never a brute-force
// wordlist or a guessed path outside that fixed set (phase8.md §15/§29:
// "no exploitation... no unrestricted crawling").
type SafeActiveFetcher interface {
	Fetch(ctx context.Context, rawURL string, maxBytes int) (FetchResult, error)
}
