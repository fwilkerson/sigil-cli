package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/sigil/identity"
)

func newTrustRetractCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "retract <attestation-id>",
		Short: "Retract a previously submitted attestation",
		Long: `Retract (soft-delete) one of your own attestations.

You must be the original attester. The retraction is authenticated by signing
a canonical deletion payload with your key.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			attestationID := args[0]
			app := appFrom(cmd)
			client := app.TrustClient()
			kp := app.KeyPair
			did := identity.DIDFromKey(kp.Public)

			if err := client.Retract(cmd.Context(), attestationID, did, kp); err != nil {
				return fmt.Errorf("retract attestation: %w", err)
			}

			if jsonFlag(cmd) {
				data, err := json.MarshalIndent(map[string]string{
					"attestation_id": attestationID,
					"status":         "retracted",
				}, "", "  ")
				if err != nil {
					return err
				}
				cmd.Println(string(data))
				return nil
			}

			cmd.Printf("Attestation retracted: %s\n", attestationID)
			return nil
		},
	}
	return cmd
}
