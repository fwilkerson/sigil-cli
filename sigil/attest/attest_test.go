package attest_test

import (
	"strings"
	"testing"

	"github.com/fwilkerson/sigil-cli/sigil/attest"
)

func TestValidateClaims_TooManyKeys(t *testing.T) {
	t.Parallel()
	m := make(map[string]string, attest.MaxClaimKeys+1)
	for i := range attest.MaxClaimKeys + 1 {
		m[strings.Repeat("k", i+1)] = "v"
	}
	if err := attest.ValidateClaims(m); err == nil {
		t.Fatal("expected error for too many keys")
	}
}

func TestValidateClaims_KeyTooLong(t *testing.T) {
	t.Parallel()
	m := map[string]string{strings.Repeat("k", attest.MaxClaimKeyLen+1): "v"}
	if err := attest.ValidateClaims(m); err == nil {
		t.Fatal("expected error for key too long")
	}
}

func TestValidateClaims_ValueTooLong(t *testing.T) {
	t.Parallel()
	m := map[string]string{"k": strings.Repeat("v", attest.MaxClaimValueLen+1)}
	if err := attest.ValidateClaims(m); err == nil {
		t.Fatal("expected error for value too long")
	}
}

func TestValidateClaims_TotalSizeTooLarge(t *testing.T) {
	t.Parallel()
	// Create claims that individually fit but collectively exceed 8KB.
	m := make(map[string]string)
	for i := range 20 {
		k := strings.Repeat("k", i+1)
		m[k] = strings.Repeat("v", attest.MaxClaimValueLen)
	}
	if err := attest.ValidateClaims(m); err == nil {
		t.Fatal("expected error for total size too large")
	}
}

func TestValidateClaims_ValidClaims(t *testing.T) {
	t.Parallel()
	m := map[string]string{
		"status": "resolved",
		"rating": "4.9",
	}
	if err := attest.ValidateClaims(m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateClaims_Nil(t *testing.T) {
	t.Parallel()
	if err := attest.ValidateClaims(nil); err != nil {
		t.Fatalf("unexpected error for nil claims: %v", err)
	}
}
