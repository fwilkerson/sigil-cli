package fsutil

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	data := []byte("hello world")

	if err := WriteFileAtomic(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestWriteFileAtomic_Permissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	if err := WriteFileAtomic(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestWriteFileAtomic_Overwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	// Write initial content.
	if err := WriteFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Overwrite with new content.
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("got %q, want %q", got, "second")
	}
}

func TestWriteFileAtomic_NoTempFileOnSuccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if err := WriteFileAtomic(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No leftover temp files should exist.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "test.txt" {
			t.Errorf("unexpected file in directory: %s", e.Name())
		}
	}
}

func TestWriteFileAtomic_InvalidDir(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nonexistent", "test.txt")

	err := WriteFileAtomic(path, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error for nonexistent parent directory")
	}
}

func TestWriteFileAtomic_EmptyData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	if err := WriteFileAtomic(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want 0", len(got))
	}
}
