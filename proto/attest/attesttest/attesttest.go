// Package attesttest provides test helpers for Sealable implementations.
// Import this package only from _test.go files to avoid pulling the testing
// package into production binaries.
package attesttest

import (
	"testing"

	"github.com/fwilkerson/sigil-cli/proto/attest"
)

// AssertDeterministicPayload verifies a Sealable implementation produces
// identical signing payloads across multiple calls. All Sealable
// implementations must pass this.
//
// It calls SigningPayload 10 times to exercise non-deterministic map ordering
// in JSON marshaling (Go randomizes map iteration order).
func AssertDeterministicPayload(t *testing.T, s attest.Sealable) {
	t.Helper()
	first, err := s.SigningPayload()
	if err != nil {
		t.Fatalf("first SigningPayload() call failed: %v", err)
	}
	for i := range 10 {
		got, err := s.SigningPayload()
		if err != nil {
			t.Fatalf("SigningPayload() call %d failed: %v", i+2, err)
		}
		if string(got) != string(first) {
			t.Fatalf("SigningPayload() not deterministic: call 1 = %q, call %d = %q", first, i+2, got)
		}
	}
}
