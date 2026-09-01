package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		result LookupResult
		want   ResolutionState
	}{
		{"NXDOMAIN", LookupResult{Rcode: dns.RcodeNameError}, StateNXDOMAIN},
		{"NOERROR with records is RESOLVED", LookupResult{Rcode: dns.RcodeSuccess, Records: []Record{{Type: TypeA, Value: "192.0.2.10"}}}, StateResolved},
		{"NOERROR with no records is NO_ANSWER (NODATA)", LookupResult{Rcode: dns.RcodeSuccess, Records: nil}, StateNoAnswer},
		{"SERVFAIL is ERROR, not NXDOMAIN or TIMEOUT", LookupResult{Rcode: dns.RcodeServerFailure}, StateError},
		{"REFUSED is ERROR", LookupResult{Rcode: dns.RcodeRefused}, StateError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.result); got != tc.want {
				t.Errorf("classify() = %s, want %s", got, tc.want)
			}
		})
	}
}

// fakeTimeoutError implements net.Error for testing classifyTransportError's
// net.Error.Timeout() branch, independent of any real network condition.
type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "fake timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

func TestClassifyTransportError(t *testing.T) {
	deadline, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-deadline.Done()

	tests := []struct {
		name string
		err  error
		want ResolutionState
	}{
		{"nil error", nil, ""},
		{"context deadline exceeded", deadline.Err(), StateTimeout},
		{"wrapped context deadline exceeded", errors.New("query failed: " + context.DeadlineExceeded.Error()), StateError}, // string-wrapping, not errors.Is-compatible: falls to ERROR, proving classifyTransportError uses errors.Is, not string matching
		{"net.Error timeout", fakeTimeoutError{}, StateTimeout},
		{"generic error", errors.New("connection refused"), StateError},
		{"net.OpError non-timeout", &net.OpError{Op: "read", Err: errors.New("refused")}, StateError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTransportError(tc.err); got != tc.want {
				t.Errorf("classifyTransportError(%v) = %s, want %s", tc.err, got, tc.want)
			}
		})
	}
}
