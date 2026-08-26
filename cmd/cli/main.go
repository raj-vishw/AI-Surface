// Command ai-recon is the platform's command-line interface.
package main

import "os"

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
