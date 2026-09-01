package network

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	domaintarget "ai-recon-platform/internal/domain/target"
)

// mustListener starts a listener that accepts and immediately closes every
// connection, for OPEN-state tests.
func mustListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return l
}

// mustClosedPort reserves and immediately releases a port so nothing is
// listening on it.
func mustClosedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("closing reserved listener: %v", err)
	}
	return port
}

func testNetworkConfig() Config {
	return Config{ConnectTimeout: 2 * time.Second, MaxConcurrency: 10}
}

func TestScanner_OpenPort(t *testing.T) {
	l := mustListener(t)
	defer func() { _ = l.Close() }()
	port := l.Addr().(*net.TCPAddr).Port

	scanner := NewScanner(nil, testNetworkConfig())
	result := scanner.connect(context.Background(), uuid.New(), uuid.New(), "127.0.0.1", port)
	if result.State != StateOpen {
		t.Errorf("State = %s, want %s", result.State, StateOpen)
	}
}

func TestScanner_ClosedPort(t *testing.T) {
	port := mustClosedPort(t)

	scanner := NewScanner(nil, testNetworkConfig())
	result := scanner.connect(context.Background(), uuid.New(), uuid.New(), "127.0.0.1", port)
	if result.State != StateClosed {
		t.Errorf("State = %s, want %s", result.State, StateClosed)
	}
	if result.Error != "" {
		t.Errorf("expected no Error for CLOSED (connection refused is informative, not a failure), got %q", result.Error)
	}
}

func TestScanner_Timeout(t *testing.T) {
	l := mustListener(t)
	defer func() { _ = l.Close() }()
	port := l.Addr().(*net.TCPAddr).Port

	// An infinitesimally short timeout against a real, reachable listener
	// reliably forces a dial timeout — a well-established, non-flaky Go
	// testing pattern that needs no real network black-holing.
	scanner := NewScanner(nil, Config{ConnectTimeout: 1 * time.Nanosecond, MaxConcurrency: 10})
	result := scanner.connect(context.Background(), uuid.New(), uuid.New(), "127.0.0.1", port)
	if result.State != StateTimeout {
		t.Errorf("State = %s, want %s", result.State, StateTimeout)
	}
}

func TestScanner_ConnectionFailure(t *testing.T) {
	// A host that cannot resolve/route (TEST-NET-1, RFC 5737) reliably
	// produces some kind of dial failure without depending on any real
	// service; whichever error state it maps to, this must never panic
	// and must produce a well-formed result.
	scanner := NewScanner(nil, Config{ConnectTimeout: 200 * time.Millisecond, MaxConcurrency: 10})
	result := scanner.connect(context.Background(), uuid.New(), uuid.New(), "192.0.2.1", 80)
	if result.State != StateTimeout && result.State != StateError {
		t.Errorf("State = %s, want TIMEOUT or ERROR for an unreachable host", result.State)
	}
}

func TestScanner_MultiplePortsAndHosts(t *testing.T) {
	l1 := mustListener(t)
	defer func() { _ = l1.Close() }()
	l2 := mustListener(t)
	defer func() { _ = l2.Close() }()
	closedPort := mustClosedPort(t)

	scanner := NewScanner(nil, testNetworkConfig())
	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetID: uuid.New(), Target: "127.0.0.1",
		Hosts: []string{"127.0.0.1"},
		Ports: []int{l1.Addr().(*net.TCPAddr).Port, l2.Addr().(*net.TCPAddr).Port, closedPort},
	}, nil)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if summary.Open != 2 {
		t.Errorf("Open = %d, want 2", summary.Open)
	}
	if summary.Closed != 1 {
		t.Errorf("Closed = %d, want 1", summary.Closed)
	}
	if summary.PortsAttempted != 3 {
		t.Errorf("PortsAttempted = %d, want 3", summary.PortsAttempted)
	}
}

func TestScanner_DuplicateTargetsDeduplicated(t *testing.T) {
	l := mustListener(t)
	defer func() { _ = l.Close() }()
	port := l.Addr().(*net.TCPAddr).Port

	scanner := NewScanner(nil, testNetworkConfig())
	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetID: uuid.New(), Target: "127.0.0.1",
		Hosts: []string{"127.0.0.1", "127.0.0.1"}, // duplicate host
		Ports: []int{port, port},                  // duplicate port
	}, nil)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if summary.PortsAttempted != 1 {
		t.Errorf("PortsAttempted = %d, want 1 (duplicate host:port pairs must collapse)", summary.PortsAttempted)
	}
}

// slowDial returns a Scanner.dial replacement that sleeps for delay before
// deferring to a real dial against l, tracking the maximum number of
// concurrently in-flight calls into maxObserved. A bare loopback TCP
// handshake completes in microseconds regardless of server-side Accept()
// pacing, so this — instrumenting the dial itself — is what reliably
// exercises MaxConcurrency/cancellation (phase4.md §40's "use
// instrumentation around connection attempts", not merely counting
// goroutines or relying on server timing).
func slowDial(l net.Listener, delay time.Duration, active, maxObserved *int32) func(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := atomic.AddInt32(active, 1)
		defer atomic.AddInt32(active, -1)
		for {
			old := atomic.LoadInt32(maxObserved)
			if n <= old || atomic.CompareAndSwapInt32(maxObserved, old, n) {
				break
			}
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return dialer.DialContext(ctx, "tcp", l.Addr().String())
	}
}

// TestScanner_BoundedConcurrencyMultiListener verifies max concurrent
// connection attempts never exceed cfg.MaxConcurrency.
func TestScanner_BoundedConcurrencyMultiListener(t *testing.T) {
	l := mustListener(t)
	defer func() { _ = l.Close() }()

	var active, maxObserved int32
	const total = 12
	const limit = 3

	scanner := NewScanner(nil, Config{ConnectTimeout: 2 * time.Second, MaxConcurrency: limit})
	scanner.dial = slowDial(l, 20*time.Millisecond, &active, &maxObserved)

	ports := make([]int, total)
	for i := range ports {
		ports[i] = 10000 + i // distinct ports so jobs aren't deduplicated; slowDial ignores the address anyway
	}

	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetID: uuid.New(), Target: "127.0.0.1", Hosts: []string{"127.0.0.1"}, Ports: ports,
	}, nil)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if summary.Open != total {
		t.Errorf("Open = %d, want %d", summary.Open, total)
	}
	if got := atomic.LoadInt32(&maxObserved); got > limit {
		t.Errorf("observed %d concurrent dial attempts, want <= %d", got, limit)
	}
}

func TestScanner_CancellationStopsPromptlyWithoutLeaks(t *testing.T) {
	l := mustListener(t)
	defer func() { _ = l.Close() }()

	var active, maxObserved int32
	const total = 30

	scanner := NewScanner(nil, Config{ConnectTimeout: 2 * time.Second, MaxConcurrency: 2})
	scanner.dial = slowDial(l, 20*time.Millisecond, &active, &maxObserved)

	ports := make([]int, total)
	for i := range ports {
		ports[i] = 10000 + i
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(15 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	// Scan's own sync.WaitGroup.Wait() means it cannot return until every
	// goroutine it started has finished — a prompt return is itself
	// evidence of no leaked goroutines (phase4.md §16/§41).
	summary, err := scanner.Scan(ctx, ScanRequest{
		TargetID: uuid.New(), Target: "127.0.0.1", Hosts: []string{"127.0.0.1"}, Ports: ports,
	}, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Scan() returned an error: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Scan() took too long to return after cancellation: %v", elapsed)
	}
	if summary.Open == total {
		t.Error("expected cancellation to prevent at least some connections from completing")
	}
}

func TestScanner_ScopeBlocksOutOfScopeHost(t *testing.T) {
	port := mustClosedPort(t)
	scope, err := NewScopeChecker(domaintarget.TypeHost, "example.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scanner := NewScanner(nil, testNetworkConfig())
	summary, err := scanner.Scan(context.Background(), ScanRequest{
		TargetID: uuid.New(), Target: "example.local",
		Hosts: []string{"out-of-scope.local"}, Ports: []int{port},
	}, scope)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}
	if len(summary.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(summary.Results))
	}
	if !summary.Results[0].Skipped {
		t.Error("expected the out-of-scope host to be skipped, not connected to")
	}
}

func TestClassifyDialError_Timeout(t *testing.T) {
	if got := classifyDialError(context.DeadlineExceeded); got != StateTimeout {
		t.Errorf("classifyDialError(DeadlineExceeded) = %s, want %s", got, StateTimeout)
	}
}

func TestBuildJobs_Deterministic(t *testing.T) {
	jobs1 := buildJobs([]string{"a", "b"}, []int{1, 2})
	jobs2 := buildJobs([]string{"a", "b"}, []int{1, 2})
	if fmt.Sprint(jobs1) != fmt.Sprint(jobs2) {
		t.Errorf("buildJobs is not deterministic: %v vs %v", jobs1, jobs2)
	}
	if len(jobs1) != 4 {
		t.Errorf("expected 4 jobs (2 hosts x 2 ports), got %d", len(jobs1))
	}
}
