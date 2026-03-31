package cmd

import (
	"strings"
	"testing"
)

func TestTrustConfigGet_DefaultAutoAttest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	buf, err := execCommand(t, dir, "trust", "config", "get", "auto-attest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "true") {
		t.Errorf("expected default auto-attest to be true, got: %s", out)
	}
}

func TestTrustConfigSetThenGet(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, err := execCommand(t, dir, "trust", "config", "set", "auto-attest", "false")
	if err != nil {
		t.Fatalf("set auto-attest false: %v", err)
	}

	buf, err := execCommand(t, dir, "trust", "config", "get", "auto-attest")
	if err != nil {
		t.Fatalf("get auto-attest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "false") {
		t.Errorf("expected auto-attest to be false after set, got: %s", out)
	}
}

func TestTrustConfigSet_BooleanAliasYes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, err := execCommand(t, dir, "trust", "config", "set", "auto-attest", "yes")
	if err != nil {
		t.Fatalf("set auto-attest yes: %v", err)
	}

	buf, err := execCommand(t, dir, "trust", "config", "get", "auto-attest")
	if err != nil {
		t.Fatalf("get auto-attest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "true") {
		t.Errorf("expected auto-attest to be true after 'yes', got: %s", out)
	}
}

func TestTrustConfigGet_UnknownKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := execCommand(t, dir, "trust", "config", "get", "unknown-key")
	if err == nil {
		t.Fatal("expected error for unknown config key")
	}
	if !strings.Contains(err.Error(), "unknown config key") {
		t.Errorf("expected 'unknown config key' error, got: %v", err)
	}
}

func TestTrustConfigSet_InvalidValue(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := execCommand(t, dir, "trust", "config", "set", "auto-attest", "banana")
	if err == nil {
		t.Fatal("expected error for invalid value")
	}
	if !strings.Contains(err.Error(), "invalid value") {
		t.Errorf("expected 'invalid value' error, got: %v", err)
	}
}
