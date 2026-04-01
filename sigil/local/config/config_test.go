package config_test

import (
	"os"
	"testing"

	"github.com/fwilkerson/sigil-cli/sigil/local/config"
)

func TestLoad_Default(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoAttestEnabled() {
		t.Error("expected auto-attest enabled by default")
	}
}

func TestLoad_Roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	aa := false
	cfg := &config.Config{AutoAttest: &aa}
	if err := config.Save(dir, cfg); err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AutoAttestEnabled() {
		t.Error("expected auto-attest disabled after save")
	}
}

func TestAutoAttestEnabled_Default(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	if !cfg.AutoAttestEnabled() {
		t.Error("expected true when AutoAttest is nil")
	}
}

func TestAutoAttestEnabled_Explicit(t *testing.T) {
	t.Parallel()

	aa := true
	cfg := &config.Config{AutoAttest: &aa}
	if !cfg.AutoAttestEnabled() {
		t.Error("expected true when explicitly set")
	}

	aa = false
	cfg = &config.Config{AutoAttest: &aa}
	if cfg.AutoAttestEnabled() {
		t.Error("expected false when explicitly set")
	}
}

func TestDir_XDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")

	dir, err := config.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != "/tmp/xdg/sigil" {
		t.Errorf("expected /tmp/xdg/sigil, got %s", dir)
	}
}

func TestDir_Fallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")

	dir, err := config.Dir()
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want := home + "/.config/sigil"
	if dir != want {
		t.Errorf("expected %s, got %s", want, dir)
	}
}
