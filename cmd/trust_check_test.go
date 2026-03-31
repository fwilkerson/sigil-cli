package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/fwilkerson/sigil-cli/sigil/trustclient"
)

func newTestCheckCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(new(bytes.Buffer))
	cmd.PersistentFlags().Bool("json", false, "")
	return cmd
}

func TestPrintCheckHuman_WithData(t *testing.T) {
	t.Parallel()
	cmd := newTestCheckCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	r := &trustclient.CheckResult{
		ToolURI:          "mcp://example.com/tool",
		Score:            0.85,
		Recommendation:   trustclient.RecommendUse,
		Label:            "well-trusted",
		HasData:          true,
		Attestations:     150,
		Attesters:        40,
		SuccessRate:      0.95,
		VersionsAttested: 3,
		LatestVersion:    "2.1.0",
	}
	printCheckHuman(cmd, r)

	out := buf.String()
	for _, want := range []string{
		"Tool: mcp://example.com/tool",
		"Recommendation: use",
		"Label: well-trusted",
		"Score: 0.85",
		"150 (40 unique attesters)",
		"3 attested (latest: 2.1.0)",
		"95%",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestPrintCheckHuman_NoData(t *testing.T) {
	t.Parallel()
	cmd := newTestCheckCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	r := &trustclient.CheckResult{
		ToolURI:        "mcp://example.com/unknown-tool",
		Score:          0,
		Recommendation: trustclient.RecommendUnknown,
		Label:          "unknown — no attestations yet",
		HasData:        false,
	}
	printCheckHuman(cmd, r)

	out := buf.String()
	if !strings.Contains(out, "unknown") {
		t.Errorf("expected 'unknown' recommendation, got:\n%s", out)
	}
	if strings.Contains(out, "Score:") {
		t.Errorf("expected no score line for unknown tool, got:\n%s", out)
	}
}

func TestPrintCheckJSON_WithData(t *testing.T) {
	t.Parallel()
	cmd := newTestCheckCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	r := &trustclient.CheckResult{
		ToolURI:          "mcp://example.com/tool",
		Score:            0.72,
		Recommendation:   trustclient.RecommendUse,
		Label:            "well-trusted",
		HasData:          true,
		Attestations:     80,
		Attesters:        25,
		SuccessRate:      0.90,
		VersionsAttested: 2,
		LatestVersion:    "1.5.0",
	}
	if err := printCheckJSON(cmd, r); err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, buf)
	}
	if got["recommendation"] != "use" {
		t.Errorf("expected recommendation 'use', got %v", got["recommendation"])
	}
	if got["attestations"].(float64) != 80 {
		t.Errorf("expected 80 attestations, got %v", got["attestations"])
	}
	if got["latest_version"] != "1.5.0" {
		t.Errorf("expected latest_version '1.5.0', got %v", got["latest_version"])
	}
}

func TestPrintCheckJSON_NoData(t *testing.T) {
	t.Parallel()
	cmd := newTestCheckCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	r := &trustclient.CheckResult{
		ToolURI:        "mcp://example.com/unknown",
		Recommendation: trustclient.RecommendUnknown,
		Label:          "unknown — no attestations yet",
		HasData:        false,
	}
	if err := printCheckJSON(cmd, r); err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, buf)
	}
	if got["recommendation"] != "unknown" {
		t.Errorf("expected 'unknown', got %v", got["recommendation"])
	}
	if _, ok := got["attestations"]; ok {
		t.Error("expected no 'attestations' field when has_data is false")
	}
}

func TestTrustCheckCmd_MissingArg(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := execCommand(t, dir, "trust", "check")
	if err == nil {
		t.Fatal("expected error for missing tool-uri argument")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Errorf("expected argument count error, got: %v", err)
	}
}
