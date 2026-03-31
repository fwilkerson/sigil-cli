package signing_test

import (
	"strings"
	"testing"

	"github.com/fwilkerson/sigil-cli/proto/signing"
)

func mustGenerateKeyPair(t *testing.T) *signing.KeyPair {
	t.Helper()
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestSignVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kp := mustGenerateKeyPair(t)
	msg := []byte("hello sigil")
	sig := signing.Sign(kp.Private, msg)

	if !signing.Verify(kp.Public, msg, sig) {
		t.Fatal("valid signature rejected")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	t.Parallel()
	kp1 := mustGenerateKeyPair(t)
	kp2 := mustGenerateKeyPair(t)

	msg := []byte("hello sigil")
	sig := signing.Sign(kp1.Private, msg)

	if signing.Verify(kp2.Public, msg, sig) {
		t.Fatal("signature from different key should not verify")
	}
}

func TestVerify_TamperedMessage(t *testing.T) {
	t.Parallel()
	kp := mustGenerateKeyPair(t)
	msg := []byte("original")
	sig := signing.Sign(kp.Private, msg)

	if signing.Verify(kp.Public, []byte("tampered"), sig) {
		t.Fatal("tampered message should not verify")
	}
}

func TestMnemonic_GenerateAndRecover(t *testing.T) {
	t.Parallel()
	kp, mnemonic, err := signing.GenerateKeyPairWithMnemonic()
	if err != nil {
		t.Fatalf("generate with mnemonic: %v", err)
	}

	words := strings.Fields(mnemonic)
	if len(words) != 12 {
		t.Fatalf("mnemonic word count: got %d, want 12", len(words))
	}

	recovered, err := signing.KeyPairFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("recover from mnemonic: %v", err)
	}

	if !kp.Public.Equal(recovered.Public) {
		t.Fatal("recovered public key doesn't match original")
	}
	if !kp.Private.Equal(recovered.Private) {
		t.Fatal("recovered private key doesn't match original")
	}
}

func TestMnemonic_Deterministic(t *testing.T) {
	t.Parallel()
	_, mnemonic, err := signing.GenerateKeyPairWithMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	kp1, err := signing.KeyPairFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := signing.KeyPairFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}

	if !kp1.Public.Equal(kp2.Public) {
		t.Fatal("same mnemonic produced different keys")
	}
}

func TestMnemonic_Invalid(t *testing.T) {
	t.Parallel()
	_, err := signing.KeyPairFromMnemonic("not a valid mnemonic phrase")
	if err == nil {
		t.Fatal("expected error for invalid mnemonic")
	}
}

func TestMnemonic_SignVerify(t *testing.T) {
	t.Parallel()
	kp, mnemonic, err := signing.GenerateKeyPairWithMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("signed before recovery")
	sig := signing.Sign(kp.Private, msg)

	recovered, err := signing.KeyPairFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	if !signing.Verify(recovered.Public, msg, sig) {
		t.Fatal("recovered key should verify signature from original")
	}
}

func TestCanonicalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"reorders keys", `{"b":2,"a":1}`, `{"a":1,"b":2}`},
		{"nested objects", `{"z":{"b":2,"a":1},"a":"first"}`, `{"a":"first","z":{"a":1,"b":2}}`},
		{"already canonical", `{"a":1,"b":2}`, `{"a":1,"b":2}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := signing.Canonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSignCanonical_RoundTrip(t *testing.T) {
	t.Parallel()
	kp := mustGenerateKeyPair(t)

	data := []byte(`{"action":"propose","amount":1099}`)
	sig, err := signing.SignCanonical(kp, data)
	if err != nil {
		t.Fatalf("sign canonical: %v", err)
	}

	// Verify with keys in different order — should still pass.
	reordered := []byte(`{"amount":1099,"action":"propose"}`)
	ok, err := signing.VerifyCanonical(kp.Public, reordered, sig)
	if err != nil {
		t.Fatalf("verify canonical: %v", err)
	}
	if !ok {
		t.Fatal("canonical verification failed for reordered JSON")
	}
}

func TestCanonicalize_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := signing.Canonicalize([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMnemonic_LeadingTrailingWhitespace(t *testing.T) {
	t.Parallel()
	// KeyPairFromMnemonic calls strings.TrimSpace before validation. Leading
	// and trailing whitespace must therefore be stripped silently, and the
	// resulting key must be identical to the one produced from the clean
	// mnemonic — no panic, no spurious error.
	_, mnemonic, err := signing.GenerateKeyPairWithMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	kpClean, err := signing.KeyPairFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("parse clean mnemonic: %v", err)
	}

	padded := "  " + mnemonic + "  "
	kpPadded, err := signing.KeyPairFromMnemonic(padded)
	if err != nil {
		t.Fatalf("parse leading/trailing-padded mnemonic: %v", err)
	}

	if !kpClean.Public.Equal(kpPadded.Public) {
		t.Fatal("leading/trailing whitespace must be stripped; keys should match")
	}
}

func TestSign_Deterministic(t *testing.T) {
	t.Parallel()
	// Ed25519 is deterministic: the same private key signing the same message
	// must always produce byte-identical signatures.
	kp := mustGenerateKeyPair(t)
	msg := []byte("deterministic signing test message")

	sig1 := signing.Sign(kp.Private, msg)
	sig2 := signing.Sign(kp.Private, msg)

	if string(sig1) != string(sig2) {
		t.Fatal("Ed25519 signatures for identical inputs must be identical")
	}
}
