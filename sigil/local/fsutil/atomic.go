// Package fsutil provides filesystem utilities for the sigil CLI.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to a temporary file in the same directory as
// path, syncs it to stable storage, then atomically renames it into place.
// This ensures the target file is never left in a partial state, even if the
// process is interrupted mid-write.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()

	// cleanup removes the temp file on any error path. After a successful
	// rename this is a no-op (tmp no longer exists at the old path).
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}

	if _, err := f.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Chmod(perm); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	// Sync flushes file data to stable storage before rename. Without this,
	// a crash could journal the rename but not the data, leaving a zero-length
	// or partial file at the destination.
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
