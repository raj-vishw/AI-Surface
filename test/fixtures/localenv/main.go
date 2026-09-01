// Command localenv starts the full local test environment phase4.md §36
// describes, for manual verification of network discovery:
//
//	127.0.0.1:8000 -> HTTP service (test/fixtures/http)
//	127.0.0.1:8080 -> HTTP service (test/fixtures/http)
//	127.0.0.1:9000 -> generic TCP service (test/fixtures/tcp)
//
// Selected ports (e.g. 8001, 9001) are deliberately left with nothing
// listening, so a scan against them observes CLOSED. Usage:
//
//	go run ./test/fixtures/localenv
//	ai-recon network-scan --target 127.0.0.1 --ports 8000,8001,8080,9000,9001 --profile quick
//
// This is a development/test tool, not part of the platform itself —
// intentionally outside cmd/ (the platform's real executables).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	httpfixture "ai-recon-platform/test/fixtures/http"
	tcpfixture "ai-recon-platform/test/fixtures/tcp"
)

func main() {
	http1, err := httpfixture.NewOnPort(8000)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal: starting HTTP fixture on :8000:", err)
		os.Exit(1)
	}
	defer http1.Close()
	fmt.Println("HTTP service listening on", http1.URL())

	http2, err := httpfixture.NewOnPort(8080)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal: starting HTTP fixture on :8080:", err)
		os.Exit(1)
	}
	defer http2.Close()
	fmt.Println("HTTP service listening on", http2.URL())

	tcpSrv, err := tcpfixture.NewOnPort(9000)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal: starting TCP fixture on :9000:", err)
		os.Exit(1)
	}
	defer func() { _ = tcpSrv.Close() }()
	fmt.Println("generic TCP service listening on", tcpSrv.Addr())

	fmt.Println("ports 8001 and 9001 are deliberately left closed (nothing listening)")
	fmt.Println("press Ctrl+C to stop")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
