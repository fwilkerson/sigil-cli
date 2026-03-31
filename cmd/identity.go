package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/internal/trustsetup"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage your Sigil identity",
	}
	cmd.AddCommand(newIdentityShowCmd(), newIdentityExportCmd())
	return cmd
}

func newIdentityShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show your Sigil identity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := configDirFrom(cmd)
			meta, err := trustsetup.LoadIdentityMeta(dir)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					cmd.Println("No identity yet. One will be created on your first attestation.")
					return nil
				}
				return fmt.Errorf("load identity: %w", err)
			}
			cmd.Printf("DID:     %s\n", meta.DID)
			cmd.Printf("Created: %s\n", meta.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
			return nil
		},
	}
}

func newIdentityExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export public identity as JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := configDirFrom(cmd)
			kp, _, err := trustsetup.LoadIdentity(dir)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("no identity exists yet — run an attestation first to create one")
				}
				return err
			}
			meta, err := trustsetup.LoadIdentityMeta(dir)
			if err != nil {
				return fmt.Errorf("load identity metadata: %w", err)
			}

			type exportData struct {
				Name      string `json:"name"`
				DID       string `json:"did"`
				PublicKey string `json:"public_key"`
				CreatedAt string `json:"created_at"`
			}
			out, err := json.MarshalIndent(exportData{
				Name:      meta.Name,
				DID:       string(meta.DID),
				PublicKey: base64.StdEncoding.EncodeToString(kp.Public),
				CreatedAt: meta.CreatedAt.Format("2006-01-02T15:04:05Z"),
			}, "", "  ")
			if err != nil {
				return err
			}
			cmd.Println(string(out))
			return nil
		},
	}
}
