package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	trustpb "github.com/fwilkerson/sigil-cli/api/trust/v1"
	"github.com/fwilkerson/sigil-cli/sigil/local"
)

// addDevTrustCommands registers dev-only trust subcommands. Overridden by
// commands_trust_dev.go in non-release builds.
var addDevTrustCommands = func(*cobra.Command) {}

type appKey struct{}

func newTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Query and submit tool trust attestations",
	}

	registerTrustAddrFlag(cmd)
	cmd.PersistentFlags().Bool("json", false, "output as JSON")

	cmd.AddCommand(
		withTrustRead(newTrustCheckCmd()),
		withTrustWrite(newTrustAttestCmd()),
		withTrustWrite(newTrustRetractCmd()),
		withTrustRead(newTrustTopCmd()),
		newTrustConfigCmd(),
	)
	addDevTrustCommands(cmd)
	return cmd
}

// withTrustRead wraps a command with a PreRunE that dials gRPC. Used by
// read-only commands that do not need an identity.
func withTrustRead(cmd *cobra.Command) *cobra.Command {
	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		app, err := local.Connect(trustAddr(cmd), configDirFrom(cmd))
		if err != nil {
			return err
		}
		go func() {
			<-cmd.Context().Done()
			_ = app.Close()
		}()
		ctx := context.WithValue(cmd.Context(), appKey{}, app)
		cmd.SetContext(ctx)
		if n := app.FlushPending(cmd.Context()); n > 0 {
			cmd.PrintErrf("Submitted %d pending attestation(s).\n", n)
		}
		return nil
	}
	return cmd
}

// withTrustWrite wraps a command with a PreRunE that loads or creates the
// auto-identity and dials gRPC. Used by write commands (attest).
func withTrustWrite(cmd *cobra.Command) *cobra.Command {
	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		app, err := local.Connect(trustAddr(cmd), configDirFrom(cmd))
		if err != nil {
			return err
		}

		created, err := app.EnsureIdentity()
		if err != nil {
			return fmt.Errorf("ensure identity: %w", err)
		}
		if created {
			cmd.PrintErrf("Created your Sigil identity: %s\n", app.DID)
		}

		go func() {
			<-cmd.Context().Done()
			_ = app.Close()
		}()
		ctx := context.WithValue(cmd.Context(), appKey{}, app)
		cmd.SetContext(ctx)
		if n := app.FlushPending(cmd.Context()); n > 0 {
			cmd.PrintErrf("Submitted %d pending attestation(s).\n", n)
		}
		return nil
	}
	return cmd
}

func appFrom(cmd *cobra.Command) *local.App {
	if v, ok := cmd.Context().Value(appKey{}).(*local.App); ok {
		return v
	}
	return nil
}

func trustClientFrom(cmd *cobra.Command) trustpb.TrustServiceClient {
	return trustpb.NewTrustServiceClient(appFrom(cmd).Conn())
}

func jsonFlag(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("json")
	return v
}

// scoreLabel returns a human-friendly interpretation of a trust score.
func scoreLabel(score float64, totalAttestations int32, provisional bool) string {
	if totalAttestations == 0 {
		return "unknown — no attestations yet"
	}
	if provisional {
		return "provisional — limited data"
	}
	switch {
	case score >= 0.8:
		return "well-trusted"
	case score >= 0.6:
		return "moderate trust"
	case score >= 0.4:
		return "mixed reviews"
	case score >= 0.2:
		return "low trust"
	default:
		return "poor trust"
	}
}
