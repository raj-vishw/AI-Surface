package commands

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"ai-surface-platform/internal/version"
)

// NewVersionCommand returns the `ai-surface version` subcommand.
func NewVersionCommand() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "ai-surface %s (commit %s, built %s)\n", info.Version, info.Commit, info.BuildDate)
			return err
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}
