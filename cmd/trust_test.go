package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/attest"
	"github.com/fwilkerson/sigil-cli/sigil/id"
	sigiltrust "github.com/fwilkerson/sigil-cli/sigil/trust"
)

func toolID(t *testing.T, uri string) id.ToolID {
	t.Helper()
	tid, err := id.NewToolID(uri)
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

// --- Top formatting tests (ungated: newTrustTopCmd stays in release) ---

func TestPrintTopJSON(t *testing.T) {
	t.Parallel()
	cmd := newTrustTopCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	now := time.Now()
	tools := []sigiltrust.ToolSummary{
		{
			ToolURI:           "mcp://example.com/tool-a",
			Score:             0.90,
			TotalAttestations: 200,
			UniqueAttesters:   50,
			SuccessRate:       0.95,
			FirstSeen:         now.AddDate(0, -3, 0),
			LastActive:        now,
		},
	}
	if err := printTopJSON(cmd, tools); err != nil {
		t.Fatal(err)
	}

	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, buf)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0]["label"] != "well-trusted" {
		t.Errorf("expected label 'well-trusted', got %v", got[0]["label"])
	}
}

func TestPrintTopHuman(t *testing.T) {
	t.Parallel()
	cmd := newTrustTopCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	now := time.Now()
	tools := []sigiltrust.ToolSummary{
		{
			ToolURI:           "mcp://example.com/tool",
			Score:             0.75,
			TotalAttestations: 80,
			UniqueAttesters:   25,
			SuccessRate:       0.88,
			FirstSeen:         now.AddDate(0, -2, 0),
			LastActive:        now,
		},
	}
	printTopHuman(cmd, tools)

	out := buf.String()
	if !strings.Contains(out, "TOOL") {
		t.Errorf("expected header with TOOL, got: %s", out)
	}
	if !strings.Contains(out, "well-trusted") {
		t.Errorf("expected 'well-trusted' label, got: %s", out)
	}
}

// --- Attest helper tests ---

func TestBuildClaims(t *testing.T) {
	t.Parallel()
	claims := buildClaims("read file", "permission denied", "readFile", `{"path":"string"}`, "EPERM")
	if len(claims) != 5 {
		t.Fatalf("expected 5 claims, got %d", len(claims))
	}
	if claims["intent"] != "read file" {
		t.Errorf("intent = %q, want %q", claims["intent"], "read file")
	}
	if claims["error_code"] != "EPERM" {
		t.Errorf("error_code = %q, want %q", claims["error_code"], "EPERM")
	}
}

func TestBuildClaims_Empty(t *testing.T) {
	t.Parallel()
	claims := buildClaims("", "", "", "", "")
	if len(claims) != 0 {
		t.Errorf("expected empty claims, got %d entries", len(claims))
	}
}

func TestPrintAttestJSON(t *testing.T) {
	t.Parallel()
	cmd := newTestCheckCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	if err := printAttestJSON(cmd, "att-123", "mcp://example.com/tool", "success", false); err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, buf)
	}
	if got["attestation_id"] != "att-123" {
		t.Errorf("attestation_id = %v, want %q", got["attestation_id"], "att-123")
	}
	if got["outcome"] != "success" {
		t.Errorf("outcome = %v, want %q", got["outcome"], "success")
	}
	if got["deduplicated"] != false {
		t.Errorf("deduplicated = %v, want false", got["deduplicated"])
	}
}

func TestPrintAttestJSON_Deduplicated(t *testing.T) {
	t.Parallel()
	cmd := newTestCheckCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	if err := printAttestJSON(cmd, "att-existing", "mcp://example.com/tool", "success", true); err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, buf)
	}
	if got["deduplicated"] != true {
		t.Errorf("deduplicated = %v, want true", got["deduplicated"])
	}
}

func TestPrintNegativeReview(t *testing.T) {
	t.Parallel()

	cmd := newTestCheckCmd()
	buf := new(bytes.Buffer)
	cmd.SetErr(buf)

	ta := &attest.ToolAttestation{
		Tool:    toolID(t, "mcp://example.com/tool"),
		Version: "1.0.0",
		Outcome: attest.OutcomeNegative,
		Claims:  map[string]string{"intent": "read file", "result": "failed"},
	}
	printNegativeReview(cmd, ta)

	out := buf.String()
	for _, want := range []string{
		"Negative Attestation Review",
		"mcp://example.com/tool",
		"1.0.0",
		"negative",
		"intent: read file",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// --- Command argument validation tests for ungated commands ---

func TestTrustAttestCmd_MissingArg(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := execCommand(t, dir, "trust", "attest", "--outcome=success")
	if err == nil {
		t.Fatal("expected error for missing tool-uri argument")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Errorf("expected argument count error, got: %v", err)
	}
}

func TestTrustAttestCmd_InvalidOutcome(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, err := execCommand(t, dir, "trust", "attest", "mcp://example.com/tool", "--outcome=neutral")
	if err == nil {
		t.Fatal("expected error for invalid outcome")
	}
	if !strings.Contains(err.Error(), "invalid outcome") {
		t.Errorf("expected 'invalid outcome' error, got: %v", err)
	}
}

func TestTrustRetractCmd_MissingArg(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := execCommand(t, dir, "trust", "retract")
	if err == nil {
		t.Fatal("expected error for missing attestation-id argument")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Errorf("expected argument count error, got: %v", err)
	}
}

func TestTrustAttestCmd_InvalidToolURI(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, err := execCommand(t, dir, "trust", "attest", "not-a-uri", "--outcome=success")
	if err == nil {
		t.Fatal("expected error for invalid tool URI")
	}
	if !strings.Contains(err.Error(), "tool ID") {
		t.Errorf("expected tool ID error, got: %v", err)
	}
}
