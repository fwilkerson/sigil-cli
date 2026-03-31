package trustsetup_test

import (
	"os"
	"testing"

	"github.com/fwilkerson/sigil-cli/internal/trustsetup"
)

func TestLoadConfig_Default(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cfg, err := trustsetup.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoAttestEnabled() {
		t.Error("expected auto-attest enabled by default")
	}
}

func TestLoadConfig_Roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cfg := &trustsetup.Config{AutoAttest: trustsetup.BoolPtr(false)}
	if err := trustsetup.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	loaded, err := trustsetup.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AutoAttestEnabled() {
		t.Error("expected auto-attest disabled after save")
	}
}

func TestAutoAttestEnabled_Default(t *testing.T) {
	t.Parallel()
	cfg := &trustsetup.Config{}
	if !cfg.AutoAttestEnabled() {
		t.Error("expected true when AutoAttest is nil")
	}
}

func TestAutoAttestEnabled_Explicit(t *testing.T) {
	t.Parallel()

	cfg := &trustsetup.Config{AutoAttest: trustsetup.BoolPtr(true)}
	if !cfg.AutoAttestEnabled() {
		t.Error("expected true when explicitly set")
	}

	cfg = &trustsetup.Config{AutoAttest: trustsetup.BoolPtr(false)}
	if cfg.AutoAttestEnabled() {
		t.Error("expected false when explicitly set")
	}
}

func TestConfigDir_XDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")

	dir, err := trustsetup.ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != "/tmp/xdg/sigil" {
		t.Errorf("expected /tmp/xdg/sigil, got %s", dir)
	}
}

func TestConfigDir_Fallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")

	dir, err := trustsetup.ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want := home + "/.config/sigil"
	if dir != want {
		t.Errorf("expected %s, got %s", want, dir)
	}
}
