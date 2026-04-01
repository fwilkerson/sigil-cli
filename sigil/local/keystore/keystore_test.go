package keystore_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fwilkerson/sigil-cli/sigil/local/keystore"
)

func TestEnsureIdentity_Creates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	kp, did, created, err := keystore.EnsureIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("expected created=true on first call")
	}
	if kp == nil {
		t.Fatal("expected non-nil keypair")
	}
	if did == "" {
		t.Fatal("expected non-empty DID")
	}

	privPath := filepath.Join(dir, "identities", "auto", "private.key")
	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key file not found: %v", err)
	}
	metaPath := filepath.Join(dir, "identities", "auto", "identity.json")
	if _, err := os.Stat(metaPath); err != nil {
		t.Errorf("identity metadata file not found: %v", err)
	}
}

func TestEnsureIdentity_Idempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, did1, created1, err := keystore.EnsureIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created1 {
		t.Error("expected created=true on first call")
	}

	_, did2, created2, err := keystore.EnsureIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Error("expected created=false on second call")
	}
	if did1 != did2 {
		t.Errorf("DID changed: %s → %s", did1, did2)
	}
}

func TestLoadIdentity_NotExists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, _, err := keystore.LoadIdentity(dir)
	if err == nil {
		t.Fatal("expected error loading non-existent identity")
	}
}

func TestLoadIdentity_AfterEnsure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, did1, _, err := keystore.EnsureIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}

	kp, did2, err := keystore.LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if kp == nil {
		t.Fatal("expected non-nil keypair")
	}
	if did1 != did2 {
		t.Errorf("DID mismatch: ensure=%s load=%s", did1, did2)
	}
}

func TestLoadIdentity_CorruptKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create a valid identity first.
	if _, _, _, err := keystore.EnsureIdentity(dir); err != nil {
		t.Fatal(err)
	}

	// Truncate the private key file.
	keyPath := filepath.Join(dir, "identities", "auto", "private.key")
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := keystore.LoadIdentity(dir)
	if err == nil {
		t.Fatal("expected error for corrupt key, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error should mention corruption, got: %v", err)
	}
}

func TestEnsureIdentity_CorruptKeyDoesNotRecreate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create a valid identity.
	if _, _, _, err := keystore.EnsureIdentity(dir); err != nil {
		t.Fatal(err)
	}

	// Corrupt the private key file.
	keyPath := filepath.Join(dir, "identities", "auto", "private.key")
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	// EnsureIdentity should return an error, not silently recreate.
	_, _, _, err := keystore.EnsureIdentity(dir)
	if err == nil {
		t.Fatal("expected error for corrupt key, got nil")
	}
}

func TestEnsureIdentity_FilePermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if _, _, _, err := keystore.EnsureIdentity(dir); err != nil {
		t.Fatal(err)
	}

	files := []string{"private.key", "public.key", "identity.json"}
	for _, name := range files {
		path := filepath.Join(dir, "identities", "auto", name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %o, want 0600", name, perm)
		}
	}
}
