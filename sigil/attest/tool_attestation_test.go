package attest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/attest"
	"github.com/fwilkerson/sigil-cli/sigil/attest/attesttest"
	"github.com/fwilkerson/sigil-cli/sigil/id"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
)

func testToolAttestation(t *testing.T, kp *signing.KeyPair) *attest.ToolAttestation {
	t.Helper()
	tool, err := id.NewToolID("mcp://github.com/user/repo")
	if err != nil {
		t.Fatal(err)
	}
	return &attest.ToolAttestation{
		ID:       id.NewToolAttestationID(),
		Attester: identity.DIDFromKey(kp.Public),
		Tool:     tool,
		Outcome:  attest.OutcomeSuccess,
		Claims:   map[string]string{attest.ClaimFunction: "search"},
		Version:  "1.2.3",
		IssuedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func TestToolAttest_SealAndVerify(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	if err := attest.Seal(ta, kp); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(ta.Signature) == 0 {
		t.Fatal("expected non-empty signature")
	}
	if err := attest.Verify(ta, kp.Public); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestToolAttest_Seal_RejectsInvalid(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Missing tool should be rejected.
	ta := testToolAttestation(t, kp)
	ta.Tool = id.ToolID{}
	if err := attest.Seal(ta, kp); err == nil {
		t.Fatal("expected Seal to reject missing tool")
	}
}

func TestToolAttest_Seal_RejectsKeyMismatch(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	err = attest.Seal(ta, wrongKey)
	if err == nil {
		t.Fatal("expected Seal to reject key/DID mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected 'does not match' error, got: %v", err)
	}
}

func TestToolAttest_Verify_WrongKey(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	if err := attest.Seal(ta, kp); err != nil {
		t.Fatal(err)
	}
	if err := attest.Verify(ta, stranger.Public); err != attest.ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestToolAttest_Verify_TamperedClaims(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	if err := attest.Seal(ta, kp); err != nil {
		t.Fatal(err)
	}

	ta.Claims[attest.ClaimFunction] = "tampered"
	if err := attest.Verify(ta, kp.Public); err != attest.ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature after tampering, got: %v", err)
	}
}

func TestToolAttest_VerifyWithResolver(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	if err := attest.Seal(ta, kp); err != nil {
		t.Fatal(err)
	}
	if err := attest.VerifyWithResolver(context.Background(), ta, identity.KeyResolver{}); err != nil {
		t.Fatalf("verify with resolver: %v", err)
	}
}

func TestToolAttest_Validate_MissingFields(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	base := func() *attest.ToolAttestation { return testToolAttestation(t, kp) }

	tests := []struct {
		name   string
		mutate func(ta *attest.ToolAttestation)
		want   string
	}{
		{"missing ID", func(ta *attest.ToolAttestation) { ta.ID = id.ToolAttestationID{} }, "missing attestation ID"},
		{"missing attester", func(ta *attest.ToolAttestation) { ta.Attester = "" }, "missing attester"},
		{"invalid attester", func(ta *attest.ToolAttestation) { ta.Attester = "not-a-did" }, "attester is not a valid DID"},
		{"missing tool", func(ta *attest.ToolAttestation) { ta.Tool = id.ToolID{} }, "missing tool"},
		{"invalid outcome", func(ta *attest.ToolAttestation) { ta.Outcome = "unknown" }, "invalid outcome"},
		{"missing issued_at", func(ta *attest.ToolAttestation) { ta.IssuedAt = time.Time{} }, "missing issued_at"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ta := base()
			tt.mutate(ta)
			err := ta.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %q, want %q", err.Error(), tt.want)
			}
		})
	}
}

func TestToolAttest_Validate_BothOutcomes(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	for _, outcome := range []attest.Outcome{attest.OutcomeSuccess, attest.OutcomeNegative} {
		t.Run(string(outcome), func(t *testing.T) {
			t.Parallel()
			ta := testToolAttestation(t, kp)
			ta.Outcome = outcome
			if err := ta.Validate(); err != nil {
				t.Fatalf("unexpected validation error for outcome %q: %v", outcome, err)
			}
		})
	}
}

func TestToolAttest_Validate_ClaimsSizeLimits(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	ta.Claims = make(map[string]string, attest.MaxClaimKeys+1)
	for i := range attest.MaxClaimKeys + 1 {
		ta.Claims[strings.Repeat("k", i+1)] = "v"
	}
	err = ta.Validate()
	if err == nil {
		t.Fatal("expected error for too many claim keys")
	}
	if !strings.Contains(err.Error(), "too many claim keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestToolAttest_PayloadDeterminism(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	attesttest.AssertDeterministicPayload(t, ta)
}

func TestToolAttest_PayloadVersion(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)
	data, err := ta.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"v":1`) && !strings.Contains(string(data), `"v": 1`) {
		t.Fatalf("payload should contain version field, got: %s", data)
	}
}

func TestToolAttest_Sealable_Interface(t *testing.T) {
	t.Parallel()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ta := testToolAttestation(t, kp)

	// ToolAttestation should satisfy attest.Sealable.
	var s attest.Sealable = ta
	if s.Signer() != ta.Attester {
		t.Fatalf("Signer() = %s, want %s", s.Signer(), ta.Attester)
	}
}
