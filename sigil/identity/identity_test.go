package identity_test

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/fwilkerson/sigil-cli/sigil/identity"
)

// base58Encode is a test-local helper that mirrors the internal encoding used
// by the identity package so we can construct DIDs with crafted payloads.
func testBase58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, alphabet[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

// makeDIDWithKeySize builds a did:key DID whose embedded key has the given
// byte length. This lets tests probe the size-validation path in PublicKey().
func makeDIDWithKeySize(size int) identity.DID {
	const multicodecEd25519 = 0xed
	var varBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(varBuf[:], multicodecEd25519)
	prefix := varBuf[:n]

	payload := make([]byte, size) // all-zero key bytes of the requested length
	buf := make([]byte, 0, len(prefix)+len(payload))
	buf = append(buf, prefix...)
	buf = append(buf, payload...)
	encoded := "z" + testBase58Encode(buf)
	return identity.DID("did:key:" + encoded)
}

func mustGenKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestDIDFromKey_RoundTrip(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)

	did := identity.DIDFromKey(pub)
	recovered, err := did.PublicKey()
	if err != nil {
		t.Fatalf("extract public key: %v", err)
	}

	if !pub.Equal(recovered) {
		t.Fatal("round-trip public key mismatch")
	}
}

func TestDIDFromKey_Format(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)
	did := identity.DIDFromKey(pub)

	s := did.String()
	if s[:9] != "did:key:z" {
		t.Fatalf("DID should start with did:key:z, got %q", s[:9])
	}
}

func TestDID_Method(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)
	did := identity.DIDFromKey(pub)

	if did.Method() != "key" {
		t.Fatalf("method: got %q, want %q", did.Method(), "key")
	}
}

func TestDID_IsZero(t *testing.T) {
	t.Parallel()
	var zero identity.DID
	if !zero.IsZero() {
		t.Fatal("zero DID should be zero")
	}

	pub := mustGenKey(t)
	did := identity.DIDFromKey(pub)
	if did.IsZero() {
		t.Fatal("generated DID should not be zero")
	}
}

func TestDID_PublicKey_InvalidPrefix(t *testing.T) {
	t.Parallel()
	did := identity.DID("did:web:example.com")
	_, err := did.PublicKey()
	if err == nil {
		t.Fatal("expected error for non-did:key")
	}
}

func TestDID_PublicKey_InvalidEncoding(t *testing.T) {
	t.Parallel()
	did := identity.DID("did:key:zINVALID0OO")
	_, err := did.PublicKey()
	if err == nil {
		t.Fatal("expected error for invalid encoding")
	}
}

func TestKeyResolver(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)
	did := identity.DIDFromKey(pub)

	resolver := identity.KeyResolver{}
	resolved, err := resolver.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if !pub.Equal(resolved) {
		t.Fatal("resolved key mismatch")
	}
}

func TestKeyResolver_WrongMethod(t *testing.T) {
	t.Parallel()
	resolver := identity.KeyResolver{}
	_, err := resolver.Resolve(context.Background(), identity.DID("did:web:example.com"))
	if err == nil {
		t.Fatal("expected error for did:web")
	}
}

func TestDIDFromKey_Deterministic(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)

	did1 := identity.DIDFromKey(pub)
	did2 := identity.DIDFromKey(pub)

	if did1 != did2 {
		t.Fatalf("same key produced different DIDs: %s vs %s", did1, did2)
	}
}

func TestDIDFromKey_UniquePerKey(t *testing.T) {
	t.Parallel()
	pub1 := mustGenKey(t)
	pub2 := mustGenKey(t)

	did1 := identity.DIDFromKey(pub1)
	did2 := identity.DIDFromKey(pub2)

	if did1 == did2 {
		t.Fatal("different keys produced same DID")
	}
}

func TestDID_Empty_Method(t *testing.T) {
	t.Parallel()
	// An empty DID should return "" from Method() without panicking.
	got := identity.DID("").Method()
	if got != "" {
		t.Fatalf("DID(\"\").Method() = %q, want \"\"", got)
	}
}

func TestDID_Empty_PublicKey(t *testing.T) {
	t.Parallel()
	// An empty DID does not have the "did:key:z" prefix, so PublicKey()
	// must return an error rather than panicking.
	_, err := identity.DID("").PublicKey()
	if err == nil {
		t.Fatal("expected error from DID(\"\").PublicKey()")
	}
}

func TestDID_PublicKey_WrongKeySize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size int
	}{
		{"too short (31 bytes)", 31},
		{"too long (33 bytes)", 33},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			did := makeDIDWithKeySize(tt.size)
			_, err := did.PublicKey()
			if err == nil {
				t.Fatalf("expected error for %d-byte key payload, got nil", tt.size)
			}
		})
	}
}
