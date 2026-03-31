package cmd

import (
	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/internal/buildinfo"
)

func registerTrustAddrFlag(_ *cobra.Command) {
	// Release builds use the hardcoded endpoint — no flag exposed.
}

func trustAddr(_ *cobra.Command) string {
	return buildinfo.TrustAddr
}
