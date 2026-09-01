package network

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

// BenchmarkScanner_Scan measures ports/sec and average latency for a
// bounded-concurrency scan against local services only (phase4.md §47 —
// no public Internet targets; the goal is catching obvious architectural
// problems like unbounded goroutines, unbounded buffering, or accidental
// serialization, not chasing an absolute throughput number).
func BenchmarkScanner_Scan(b *testing.B) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	openPort := l.Addr().(*net.TCPAddr).Port

	const portsPerScan = 200
	ports := make([]int, portsPerScan)
	ports[0] = openPort

	// buildJobs deduplicates identical host:port pairs (phase4.md §39), so
	// the "closed" ports must be genuinely distinct from each other and
	// from openPort. Reserving them one at a time (bind, record, close,
	// repeat) risks the OS immediately reassigning a just-freed ephemeral
	// port to the next Listen call — so every reservation listener is
	// kept open simultaneously (guaranteeing distinct ports) and only
	// closed once every port number is already recorded.
	var reserved []net.Listener
	for i := 1; i < portsPerScan; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatalf("reserving closed port: %v", err)
		}
		reserved = append(reserved, l)
		ports[i] = l.Addr().(*net.TCPAddr).Port
	}
	for _, l := range reserved {
		_ = l.Close()
	}

	scanner := NewScanner(nil, Config{ConnectTimeout: 500 * time.Millisecond, MaxConcurrency: 50})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summary, err := scanner.Scan(context.Background(), ScanRequest{
			TargetID: uuid.New(), Target: "127.0.0.1", Hosts: []string{"127.0.0.1"}, Ports: ports,
		}, nil)
		if err != nil {
			b.Fatalf("Scan() failed: %v", err)
		}
		if summary.PortsAttempted != portsPerScan {
			b.Fatalf("PortsAttempted = %d, want %d", summary.PortsAttempted, portsPerScan)
		}
	}
	b.ReportMetric(float64(portsPerScan*b.N)/b.Elapsed().Seconds(), "ports/sec")
}
