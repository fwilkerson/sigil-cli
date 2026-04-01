package cmd

import (
	"encoding/json"
	"time"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/sigil/local/scorecache"
	localtrust "github.com/fwilkerson/sigil-cli/sigil/local/trust"
)

func newTrustCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <tool-uri>",
		Short: "Check trust score for a tool",
		Long: `Query the Sigil trust service for a tool's trust score and return a
recommendation: "use" (well-trusted), "caution" (limited data or mixed),
"avoid" (poorly trusted), or "unknown" (no attestations yet).

Agents should call this before invoking a tool to decide whether to proceed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outcome, err := appFrom(cmd).Check(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			if outcome.IsCached() {
				if jsonFlag(cmd) {
					return printCachedCheckJSON(cmd, outcome.Cached)
				}
				printCachedCheckHuman(cmd, outcome.Cached)
				return nil
			}

			if jsonFlag(cmd) {
				return printCheckJSON(cmd, outcome.Live)
			}
			printCheckHuman(cmd, outcome.Live)
			return nil
		},
	}
}

func printCheckJSON(cmd *cobra.Command, r *localtrust.CheckResult) error {
	out := map[string]any{
		"tool":           r.ToolURI,
		"score":          r.Score,
		"recommendation": string(r.Recommendation),
		"label":          r.Label,
		"has_data":       r.HasData,
		"provisional":    r.Provisional,
	}
	if r.HasData {
		out["attestations"] = r.Attestations
		out["attesters"] = r.Attesters
		out["success_rate"] = r.SuccessRate
		if r.VersionsAttested > 0 {
			out["versions_attested"] = r.VersionsAttested
			out["latest_version"] = r.LatestVersion
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(data))
	return nil
}

func printCheckHuman(cmd *cobra.Command, r *localtrust.CheckResult) {
	cmd.Printf("Tool: %s\n", r.ToolURI)
	cmd.Printf("Recommendation: %s\n", r.Recommendation)
	cmd.Printf("Label: %s\n", r.Label)

	if !r.HasData {
		return
	}

	cmd.Printf("Score: %.2f\n", r.Score)
	cmd.Printf("Attestations: %d (%d unique attesters)\n", r.Attestations, r.Attesters)
	if r.VersionsAttested > 0 {
		cmd.Printf("Versions: %d attested (latest: %s)\n", r.VersionsAttested, r.LatestVersion)
	}
	cmd.Printf("Success rate: %.0f%%\n", r.SuccessRate*100)
}

func printCachedCheckJSON(cmd *cobra.Command, cs *scorecache.CachedScore) error {
	out := map[string]any{
		"tool":           cs.ToolURI,
		"score":          cs.Score,
		"recommendation": cs.Recommendation,
		"label":          cs.Label,
		"has_data":       cs.HasData,
		"provisional":    cs.Provisional,
		"cached":         true,
		"cached_at":      cs.CachedAt.UTC().Format(time.RFC3339),
	}
	if cs.HasData {
		out["attestations"] = cs.Attestations
		out["attesters"] = cs.Attesters
		out["success_rate"] = cs.SuccessRate
		if cs.VersionsAttested > 0 {
			out["versions_attested"] = cs.VersionsAttested
			out["latest_version"] = cs.LatestVersion
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(data))
	return nil
}

func printCachedCheckHuman(cmd *cobra.Command, cs *scorecache.CachedScore) {
	cmd.Printf("Tool: %s [cached]\n", cs.ToolURI)
	cmd.Printf("Cached at: %s\n", cs.CachedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	cmd.Printf("Recommendation: %s\n", cs.Recommendation)
	cmd.Printf("Label: %s\n", cs.Label)

	if !cs.HasData {
		return
	}

	cmd.Printf("Score: %.2f\n", cs.Score)
	cmd.Printf("Attestations: %d (%d unique attesters)\n", cs.Attestations, cs.Attesters)
	if cs.VersionsAttested > 0 {
		cmd.Printf("Versions: %d attested (latest: %s)\n", cs.VersionsAttested, cs.LatestVersion)
	}
	cmd.Printf("Success rate: %.0f%%\n", cs.SuccessRate*100)
}
