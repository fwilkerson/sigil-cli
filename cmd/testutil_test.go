package cmd

import (
	"bytes"
	"testing"
)

// execCommand runs a command against the given config dir, returning output and any error.
func execCommand(t *testing.T, dir string, args ...string) (*bytes.Buffer, error) {
	t.Helper()
	cmd := newRootCmd()
	if err := cmd.PersistentFlags().Set("config-dir", dir); err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	return buf, cmd.Execute()
}
