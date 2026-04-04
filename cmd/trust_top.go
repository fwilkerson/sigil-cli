package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	localtrust "github.com/fwilkerson/sigil-cli/sigil/local/trust"
	sigiltrust "github.com/fwilkerson/sigil-cli/sigil/trust"
)

func newTrustTopCmd() *cobra.Command {
	var (
		days  int32
		limit int32
	)

	cmd := &cobra.Command{
		Use:   "top",
		Short: "List top tools by trust score",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tools, err := appFrom(cmd).ListTopTools(cmd.Context(), days, limit)
			if err != nil {
				return fmt.Errorf("trust service unreachable: %w", err)
			}

			if len(tools) == 0 {
				cmd.Println("No tools found.")
				return nil
			}

			if jsonFlag(cmd) {
				return printTopJSON(cmd, tools)
			}
			printTopHuman(cmd, tools)
			return nil
		},
	}

	cmd.Flags().Int32Var(&days, "days", 30, "time window in days")
	cmd.Flags().Int32Var(&limit, "limit", 20, "maximum number of tools to show")
	return cmd
}

func printTopJSON(cmd *cobra.Command, tools []sigiltrust.ToolSummary) error {
	type entry struct {
		ToolURI           string  `json:"tool_uri"`
		Score             float64 `json:"score"`
		Label             string  `json:"label"`
		TotalAttestations int     `json:"total_attestations"`
		UniqueAttesters   int     `json:"unique_attesters"`
		SuccessRate       float64 `json:"success_rate"`
		Provisional       bool    `json:"provisional"`
		FirstSeen         string  `json:"first_seen,omitempty"`
		LastActive        string  `json:"last_active,omitempty"`
	}
	var entries []entry
	for _, t := range tools {
		_, label := localtrust.Recommend(t.Score, t.TotalAttestations, t.Provisional)
		e := entry{
			ToolURI:           t.ToolURI,
			Score:             t.Score,
			Label:             label,
			TotalAttestations: t.TotalAttestations,
			UniqueAttesters:   t.UniqueAttesters,
			SuccessRate:       t.SuccessRate,
			Provisional:       t.Provisional,
		}
		if !t.FirstSeen.IsZero() {
			e.FirstSeen = t.FirstSeen.Format("2006-01-02")
		}
		if !t.LastActive.IsZero() {
			e.LastActive = t.LastActive.Format("2006-01-02")
		}
		entries = append(entries, e)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(data))
	return nil
}

func printTopHuman(cmd *cobra.Command, tools []sigiltrust.ToolSummary) {
	cmd.Printf("%-40s  %6s  %-24s  %6s  %8s\n", "TOOL", "SCORE", "LABEL", "ATTEST", "SUCCESS")
	for _, t := range tools {
		_, label := localtrust.Recommend(t.Score, t.TotalAttestations, t.Provisional)
		cmd.Printf("%-40s  %6.2f  %-24s  %6d  %7.0f%%\n",
			t.ToolURI,
			t.Score,
			label,
			t.TotalAttestations,
			t.SuccessRate*100,
		)
	}
}
