// Command ai-recon is the platform's command-line interface.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// SIGINT/SIGTERM cancel the root context, which every subcommand that
	// does long-running work (currently: scan) threads through to the
	// HTTP client and database calls it makes — see phase3.md §44.
	// Cobra defaults an un-set context to context.Background() on its own
	// (see (*Command).Context), so commands that don't need cancellation
	// are unaffected by wiring one up here.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
