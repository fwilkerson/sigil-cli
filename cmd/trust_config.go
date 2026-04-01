package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/internal/trustsetup"
)

func newTrustConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage trust configuration",
	}
	cmd.AddCommand(newTrustConfigGetCmd(), newTrustConfigSetCmd())
	return cmd
}

func newTrustConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a config value",
		Long:  "Supported keys: auto-attest",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := trustsetup.LoadConfig(configDirFrom(cmd))
			if err != nil {
				return err
			}
			switch args[0] {
			case "auto-attest":
				cmd.Println(cfg.AutoAttestEnabled())
			default:
				return fmt.Errorf("unknown config key: %q", args[0])
			}
			return nil
		},
	}
}

func newTrustConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a config value",
		Long:  "Supported keys: auto-attest (true/false)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := configDirFrom(cmd)
			cfg, err := trustsetup.LoadConfig(dir)
			if err != nil {
				return err
			}
			switch args[0] {
			case "auto-attest":
				v := strings.ToLower(args[1])
				switch v {
				case "true", "1", "yes":
					aa := true
					cfg.AutoAttest = &aa
				case "false", "0", "no":
					aa := false
					cfg.AutoAttest = &aa
				default:
					return fmt.Errorf("invalid value %q: must be true or false", args[1])
				}
			default:
				return fmt.Errorf("unknown config key: %q", args[0])
			}
			if err := trustsetup.SaveConfig(dir, cfg); err != nil {
				return err
			}
			cmd.Printf("%s = %s\n", args[0], args[1])
			return nil
		},
	}
}
