// Command dnsserver starts the local DNS discovery test fixture
// (test/fixtures/dns) on a fixed UDP port, for manual verification of
// Phase 5 (phase5.md §72-§78) — e.g.:
//
//	go run ./test/fixtures/dns/cmd/dnsserver -port 5300
//	ai-recon dns-scan --target example.test --resolvers 127.0.0.1:5300 --profile quick
//
// This is a development/test tool, not part of the platform itself; it is
// intentionally outside cmd/ (which holds the platform's real
// executables — server, cli, worker, migrate).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	dnsfixture "ai-recon-platform/test/fixtures/dns"
)

func main() {
	port := flag.Int("port", 5300, "UDP port to listen on")
	flag.Parse()

	server, err := dnsfixture.NewOnPort(*port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
	defer func() { _ = server.Close() }()

	fmt.Printf("DNS fixture listening on %s (UDP)\n", server.Addr())
	fmt.Println("zone: example.test, api.example.test, dev.example.test, staging.example.test,")
	fmt.Println("      backend.example.test, service.example.test (CNAME), wildcard.example.test (+ *.wildcard),")
	fmt.Println("      missing.example.test (deliberately absent -> NXDOMAIN)")
	fmt.Println("press Ctrl+C to stop")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
