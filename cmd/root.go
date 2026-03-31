// Package cmd implements the sigil CLI commands.
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/internal/buildinfo"
	"github.com/fwilkerson/sigil-cli/internal/trustsetup"
	"github.com/fwilkerson/sigil-cli/internal/versioncheck"
)

// addDevCommands registers dev-only commands on the root. Overridden by
// commands_dev.go in non-release builds.
var addDevCommands = func(*cobra.Command) {}

type (
	configDirKey      struct{}
	nonInteractiveKey struct{}
)

func newRootCmd() *cobra.Command {
	var (
		configDir      string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:     "sigil",
		Version: buildinfo.Version,
		Short:   "Cryptographic trust scores for AI agent tools",
		Long: `Sigil provides cryptographically-signed trust scores for AI agent tools.

Check trust scores before using a tool, submit attestations after, and
browse the leaderboard. Your identity is a DID (decentralized identifier)
created automatically on first use.

Quick start:
  sigil trust check <tool-uri>        Check a tool's trust score
  sigil trust attest <tool-uri>       Submit an attestation after tool use
  sigil trust top                     View the trust leaderboard
  sigil identity show                 Show your identity`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			dir := configDir
			if dir == "" {
				d, err := trustsetup.ConfigDir()
				if err != nil {
					return fmt.Errorf("resolve config dir: %w", err)
				}
				dir = d
			}
			ctx := context.WithValue(cmd.Context(), configDirKey{}, dir)

			ni := nonInteractive
			if !ni && os.Getenv("SIGIL_NON_INTERACTIVE") == "1" {
				ni = true
			}
			ctx = context.WithValue(ctx, nonInteractiveKey{}, ni)

			cmd.SetContext(ctx)
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, _ []string) {
			if cmd.Name() == "version" {
				return
			}
			dir, ok := cmd.Context().Value(configDirKey{}).(string)
			if !ok {
				return
			}
			if msg := versioncheck.Check(cmd.Context(), buildinfo.Version, buildinfo.VersionURL, dir); msg != "" {
				fmt.Fprintln(cmd.ErrOrStderr())
				fmt.Fprintln(cmd.ErrOrStderr(), msg)
			}
		},
	}

	// Cobra's cmd.Print* defaults to stderr when no outWriter is set.
	// Set stdout explicitly so structured output (JSON, etc.) is pipeable.
	cmd.SetOut(os.Stdout)

	cmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "config directory (default: $XDG_CONFIG_HOME/sigil)")
	cmd.PersistentFlags().BoolVar(&nonInteractive, "non-interactive", false, "skip all interactive prompts")
	cmd.AddCommand(newTrustCmd(), newIdentityCmd(), newVersionCmd())
	addDevCommands(cmd)
	return cmd
}

// Execute runs the root command.
func Execute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return newRootCmd().ExecuteContext(ctx)
}

func configDirFrom(cmd *cobra.Command) string {
	if v, ok := cmd.Context().Value(configDirKey{}).(string); ok {
		return v
	}
	return ""
}

func isNonInteractive(cmd *cobra.Command) bool {
	if v, ok := cmd.Context().Value(nonInteractiveKey{}).(bool); ok {
		return v
	}
	return false
}
