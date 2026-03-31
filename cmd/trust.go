package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/internal/pending"
	"github.com/fwilkerson/sigil-cli/internal/trustsetup"
	trustpb "github.com/fwilkerson/sigil-cli/api/trust/v1"
)

// addDevTrustCommands registers dev-only trust subcommands. Overridden by
// commands_trust_dev.go in non-release builds.
var addDevTrustCommands = func(*cobra.Command) {}

type trustSetupKey struct{}

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
		addr := trustAddr(cmd)
		setup, err := trustsetup.Connect(addr)
		if err != nil {
			return err
		}
		go func() {
			<-cmd.Context().Done()
			_ = setup.Close()
		}()
		ctx := context.WithValue(cmd.Context(), trustSetupKey{}, setup)
		cmd.SetContext(ctx)
		flushPending(cmd, setup)
		return nil
	}
	return cmd
}

// withTrustWrite wraps a command with a PreRunE that loads or creates the
// auto-identity and dials gRPC. Used by write commands (attest).
func withTrustWrite(cmd *cobra.Command) *cobra.Command {
	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		dir := configDirFrom(cmd)

		kp, did, created, err := trustsetup.EnsureIdentity(dir)
		if err != nil {
			return fmt.Errorf("ensure identity: %w", err)
		}
		if created {
			fmt.Fprintf(cmd.ErrOrStderr(), "Created your Sigil identity: %s\n", did)
		}

		addr := trustAddr(cmd)
		setup, err := trustsetup.Connect(addr)
		if err != nil {
			return err
		}
		setup.KeyPair = kp
		setup.DID = did

		go func() {
			<-cmd.Context().Done()
			_ = setup.Close()
		}()
		ctx := context.WithValue(cmd.Context(), trustSetupKey{}, setup)
		cmd.SetContext(ctx)
		flushPending(cmd, setup)
		return nil
	}
	return cmd
}

// flushPending submits any queued attestations now that gRPC is available.
// Prints a summary to stderr if anything was flushed. Errors are silently
// ignored — flush is best-effort and should never block the main command.
func flushPending(cmd *cobra.Command, setup *trustsetup.TrustSetup) {
	queue := pending.New(configDirFrom(cmd))
	plist, err := queue.Pending()
	if err != nil || len(plist) == 0 {
		return
	}
	sub := trustsetup.NewSubmitter(setup.Conn)
	submitted, _, _ := queue.Flush(cmd.Context(), sub)
	if submitted > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "Submitted %d pending attestation(s).\n", submitted)
	}
}

func trustSetupFrom(cmd *cobra.Command) *trustsetup.TrustSetup {
	if v, ok := cmd.Context().Value(trustSetupKey{}).(*trustsetup.TrustSetup); ok {
		return v
	}
	return nil
}

func trustClientFrom(cmd *cobra.Command) trustpb.TrustServiceClient {
	return trustpb.NewTrustServiceClient(trustSetupFrom(cmd).Conn)
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
