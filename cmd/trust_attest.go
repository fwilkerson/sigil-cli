package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/sigil/attest"
	"github.com/fwilkerson/sigil-cli/sigil/id"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/local/config"
	"github.com/fwilkerson/sigil-cli/sigil/local/pending"
)

func newTrustAttestCmd() *cobra.Command {
	var (
		outcome   string
		version   string
		intent    string
		resultMsg string
		function  string
		params    string
		errorCode string
		yes       bool
	)

	cmd := &cobra.Command{
		Use:   "attest <tool-uri>",
		Short: "Submit a signed trust attestation for a tool",
		Long: `Submit a positive or negative attestation for a tool.

Positive attestations are automatic and silent — they include only the tool
URI, outcome, and version. Positive attestations are automatically deduplicated:
one per tool+version per session (or once per 24 hours if no version is
provided).

Negative attestations require pre-submission review. Structured claims from the
failure context are shown before submission. Use --yes to skip confirmation.

Always pass --version when available for the best signal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			toolURI := args[0]
			setup := trustSetupFrom(cmd)
			client := setup.TrustClient()
			kp := setup.KeyPair

			o := attest.Outcome(outcome)
			switch o {
			case attest.OutcomeSuccess:
				cfg, err := config.Load(configDirFrom(cmd))
				if err != nil {
					return err
				}
				if !cfg.AutoAttestEnabled() {
					cmd.PrintErrln("Auto-attestation disabled. Skipping.")
					return nil
				}

				// Build and sign locally so we have the signed data if the
				// submit fails and we need to queue it.
				if !client.Limiter().Allow(toolURI) {
					if jsonFlag(cmd) {
						cmd.Println(`{"status": "rate_limited"}`)
					} else {
						cmd.PrintErrln("Attestation skipped (rate limited).")
					}
					return nil
				}

				toolID, err := id.NewToolID(toolURI)
				if err != nil {
					return fmt.Errorf("invalid tool URI: %w", err)
				}
				now := time.Now().UTC().Truncate(time.Second)
				ta := &attest.ToolAttestation{
					ID:       id.NewToolAttestationID(),
					Attester: identity.DIDFromKey(kp.Public),
					Tool:     toolID,
					Outcome:  attest.OutcomeSuccess,
					Claims:   map[string]string{},
					Version:  version,
					IssuedAt: now,
				}
				if err := attest.Seal(ta, kp); err != nil {
					return fmt.Errorf("seal attestation: %w", err)
				}

				result, err := client.SubmitSealed(cmd.Context(), ta)
				if err != nil {
					if qErr := enqueueAttestation(cmd, ta); qErr != nil {
						return fmt.Errorf("attest positive: %w (also failed to queue: %v)", err, qErr)
					}
					cmd.PrintErrln("Attestation queued for submission when server is available.")
					if jsonFlag(cmd) {
						cmd.Println(`{"status": "queued"}`)
					}
					return nil
				}
				if result.Deduplicated {
					if jsonFlag(cmd) {
						return printAttestJSON(cmd, result.AttestationID, toolURI, "success", true)
					}
					cmd.Printf("Already attested for this tool. Existing attestation: %s\n", result.AttestationID)
					return nil
				}
				if jsonFlag(cmd) {
					return printAttestJSON(cmd, result.AttestationID, toolURI, "success", false)
				}
				cmd.Printf("Attestation submitted: %s\n", result.AttestationID)
				return nil

			case attest.OutcomeNegative:
				claims := buildClaims(intent, resultMsg, function, params, errorCode)

				ta, err := client.PrepareNegative(toolURI, version, claims, kp)
				if err != nil {
					return fmt.Errorf("prepare negative attestation: %w", err)
				}

				if yes || isNonInteractive(cmd) {
					printNegativeReview(cmd, ta)
				} else if !confirmNegative(cmd, ta) {
					cmd.PrintErrln("Attestation cancelled.")
					return nil
				}

				result, err := client.SubmitPrepared(cmd.Context(), ta, kp)
				if err != nil {
					if qErr := enqueueAttestation(cmd, ta); qErr != nil {
						return fmt.Errorf("submit attestation: %w (also failed to queue: %v)", err, qErr)
					}
					cmd.PrintErrln("Attestation queued for submission when server is available.")
					if jsonFlag(cmd) {
						cmd.Println(`{"status": "queued"}`)
					}
					return nil
				}
				if jsonFlag(cmd) {
					return printAttestJSON(cmd, result.AttestationID, toolURI, "negative", false)
				}
				cmd.Printf("Attestation submitted: %s\n", result.AttestationID)
				return nil

			default:
				return fmt.Errorf("invalid outcome %q: must be %q or %q",
					outcome, attest.OutcomeSuccess, attest.OutcomeNegative)
			}
		},
	}

	cmd.Flags().StringVar(&outcome, "outcome", "success", "attestation outcome (success or negative)")
	cmd.Flags().StringVar(&version, "version", "", "tool version")
	cmd.Flags().StringVar(&intent, "intent", "", "what the user/agent was trying to do")
	cmd.Flags().StringVar(&resultMsg, "result", "", "what actually happened")
	cmd.Flags().StringVar(&function, "function", "", "the function/endpoint that was called")
	cmd.Flags().StringVar(&params, "params", "", "parameter shapes (JSON string)")
	cmd.Flags().StringVar(&errorCode, "error-code", "", "machine-readable error code")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip confirmation for negative attestations")
	return cmd
}

func buildClaims(intent, result, function, params, errorCode string) map[string]string {
	claims := make(map[string]string)
	if intent != "" {
		claims["intent"] = intent
	}
	if result != "" {
		claims["result"] = result
	}
	if function != "" {
		claims["function"] = function
	}
	if params != "" {
		claims["params"] = params
	}
	if errorCode != "" {
		claims["error_code"] = errorCode
	}
	return claims
}

// printNegativeReview writes the negative attestation review block to stderr.
func printNegativeReview(cmd *cobra.Command, ta *attest.ToolAttestation) {
	cmd.PrintErrln()
	cmd.PrintErrln("=== Negative Attestation Review ===")
	cmd.PrintErrf("Tool:    %s\n", ta.Tool)
	cmd.PrintErrf("Version: %s\n", ta.Version)
	cmd.PrintErrf("Outcome: %s\n", ta.Outcome)
	if len(ta.Claims) > 0 {
		cmd.PrintErrln("Claims:")
		for k, v := range ta.Claims {
			cmd.PrintErrf("  %s: %s\n", k, v)
		}
	}
	cmd.PrintErrf("Attester: %s\n", ta.Attester)
	cmd.PrintErrln("===================================")
	cmd.PrintErrln()
}

// confirmNegative shows the negative attestation for mandatory pre-submission
// review and returns true only if the user confirms.
func confirmNegative(cmd *cobra.Command, ta *attest.ToolAttestation) bool {
	printNegativeReview(cmd, ta)
	cmd.PrintErr("Submit this attestation? [y/N] ")

	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}

// enqueueAttestation writes ta to the pending queue so it can be submitted
// on the next successful connection to the trust service.
func enqueueAttestation(cmd *cobra.Command, ta *attest.ToolAttestation) error {
	queue := pending.New(configDirFrom(cmd))
	pa := &pending.Attestation{
		AttestationID: ta.ID.String(),
		AttesterDID:   string(ta.Attester),
		ToolURI:       ta.Tool.String(),
		Outcome:       string(ta.Outcome),
		Claims:        ta.Claims,
		Version:       ta.Version,
		Signature:     ta.Signature,
		IssuedAt:      ta.IssuedAt,
		QueuedAt:      time.Now().UTC(),
	}
	return queue.Enqueue(pa)
}

func printAttestJSON(cmd *cobra.Command, attID, toolURI, outcome string, deduplicated bool) error {
	out := map[string]any{
		"attestation_id": attID,
		"tool":           toolURI,
		"outcome":        outcome,
		"deduplicated":   deduplicated,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(data))
	return nil
}
