//go:build linux && !android && with_dae

package main

import (
	"github.com/daeuniverse/dae/ebpfinbound"
	"github.com/spf13/cobra"
)

var commandToolsDAE = &cobra.Command{
	Use:   "dae",
	Short: "Manage the dae eBPF capture runtime",
}

var commandToolsDAECleanupStale = &cobra.Command{
	Use:   "cleanup-stale",
	Short: "Remove resources recorded by an inactive dae eBPF runtime",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ebpfinbound.CleanupStale(cmd.Context())
	},
}

func init() {
	commandToolsDAE.AddCommand(commandToolsDAECleanupStale)
	commandTools.AddCommand(commandToolsDAE)
}
