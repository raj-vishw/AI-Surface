// Command fixtureserver starts the local HTTP discovery test fixture
// (test/fixtures/http) on a fixed port, for manual verification of Phase 3
// (phase3.md §49/§50) — e.g.:
//
//	go run ./test/fixtures/http/cmd/fixtureserver -port 9000
//	ai-recon scan --target http://127.0.0.1:9000 --profile quick
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

	httpfixture "ai-recon-platform/test/fixtures/http"
)

func main() {
	port := flag.Int("port", 9000, "port to listen on")
	flag.Parse()

	server, err := httpfixture.NewOnPort(*port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
	defer server.Close()

	fmt.Printf("fixture server listening on %s\n", server.URL())
	fmt.Println("handlers: / /openapi.json /v1/models /v1/chat/completions /health /redirect /large-response /error")
	fmt.Println("press Ctrl+C to stop")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
