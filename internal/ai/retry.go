package ai

import (
	"context"
	"time"
)

// retryingProvider wraps a Provider with bounded, deterministic retries
// (phase13.md §57: "retries must be bounded, deterministic where
// possible... do not create infinite retry loops"). A fixed backoff is
// used rather than exponential/jittered — deterministic here means no
// randomness at all, which matters for internal/service/ai's own
// determinism tests when a test provider is made to fail a fixed number
// of times.
type retryingProvider struct {
	inner      Provider
	maxRetries int
	backoff    time.Duration
}

// WithRetries returns p wrapped with up to maxRetries additional attempts
// (so maxRetries=0 means "try exactly once") after a fixed backoff
// between attempts. maxRetries<0 is treated as 0.
func WithRetries(p Provider, maxRetries int, backoff time.Duration) Provider {
	if maxRetries < 0 {
		maxRetries = 0
	}
	if backoff < 0 {
		backoff = 0
	}
	return &retryingProvider{inner: p, maxRetries: maxRetries, backoff: backoff}
}

func (r *retryingProvider) Name() string { return r.inner.Name() }

func (r *retryingProvider) Generate(ctx context.Context, req Request) (ProviderResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(r.backoff):
			case <-ctx.Done():
				return ProviderResponse{}, ctx.Err()
			}
		}
		resp, err := r.inner.Generate(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return ProviderResponse{}, ctx.Err()
		}
	}
	return ProviderResponse{}, lastErr
}
