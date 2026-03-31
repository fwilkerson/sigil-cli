package cmd

import (
	"bytes"
	"testing"
)

// makeExec returns a function that creates a fresh root command wired to dir,
// executes it with the given args, and returns captured output. It fatals on
// execution errors — use execCommand instead when you need the error value.
func makeExec(t *testing.T, dir string) func(args ...string) *bytes.Buffer {
	t.Helper()
	return func(args ...string) *bytes.Buffer {
		t.Helper()
		cmd := newRootCmd()
		if err := cmd.PersistentFlags().Set("config-dir", dir); err != nil {
			t.Fatal(err)
		}
		buf := new(bytes.Buffer)
		cmd.SetOut(buf)
		cmd.SetErr(buf)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute %v: %v", args, err)
		}
		return buf
	}
}

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
