package cmd

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fwilkerson/sigil-cli/sigil/local/keystore"
)

func TestIdentityShow_NoIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	buf, err := execCommand(t, dir, "identity", "show")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No identity yet") {
		t.Errorf("expected 'No identity yet' message, got: %s", out)
	}
}

func TestIdentityShow_WithIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, did, _, err := keystore.EnsureIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := execCommand(t, dir, "identity", "show")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, string(did)) {
		t.Errorf("expected DID %s in output, got: %s", did, out)
	}
	if !strings.Contains(out, "Created:") {
		t.Errorf("expected 'Created:' in output, got: %s", out)
	}
}

func TestIdentityExport_NoIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := execCommand(t, dir, "identity", "export")
	if err == nil {
		t.Fatal("expected error when no identity exists")
	}
}

func TestIdentityExport_WithIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, _, _, err := keystore.EnsureIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := execCommand(t, dir, "identity", "export")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	var got struct {
		DID       string `json:"did"`
		PublicKey string `json:"public_key"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("export output is not valid JSON: %v\nOutput: %s", err, out)
	}
	if !strings.HasPrefix(got.DID, "did:key:z") {
		t.Errorf("expected DID starting with 'did:key:z', got %q", got.DID)
	}
	if got.PublicKey == "" {
		t.Errorf("expected non-empty public_key in export JSON")
	}
	if got.CreatedAt == "" {
		t.Errorf("expected non-empty created_at in export JSON")
	}
}

func TestIdentityExport_JSONValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, _, _, err := keystore.EnsureIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := execCommand(t, dir, "identity", "export")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	var got struct {
		Name      string `json:"name"`
		DID       string `json:"did"`
		PublicKey string `json:"public_key"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("export output is not valid JSON: %v\nOutput: %s", err, out)
	}

	decoded, err := base64.StdEncoding.DecodeString(got.PublicKey)
	if err != nil {
		t.Fatalf("public_key is not valid base64: %v", err)
	}
	if len(decoded) == 0 {
		t.Error("decoded public_key is empty")
	}
}
