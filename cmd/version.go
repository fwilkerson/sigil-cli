package cmd

import (
	"runtime"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/cmd/buildinfo"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("sigil %s\n", buildinfo.Version)
			cmd.Printf("commit: %s\n", buildinfo.Commit)
			cmd.Printf("go: %s\n", runtime.Version())
			cmd.Printf("os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			if buildinfo.Version == "dev" {
				cmd.PrintErrln("build: dev (all commands)")
			} else {
				cmd.PrintErrln("build: release")
			}
		},
	}
}
