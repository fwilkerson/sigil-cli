// Package identity provides DID (Decentralized Identifier) types and
// the did:key method for Ed25519 public keys.
package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// DID represents a Decentralized Identifier string.
type DID string

// multicodecEd25519 is the multicodec prefix for Ed25519 public keys (0xed).
const multicodecEd25519 = 0xed

// multicodecPrefix returns the unsigned-varint encoding of the given codec
// value as a byte slice. For Ed25519 (0xed) this produces [0xed, 0x01].
func multicodecPrefix(codec uint64) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], codec)
	return buf[:n]
}

// DIDFromKey creates a did:key DID from an Ed25519 public key.
// Format: did:key:z<multibase-base58btc(multicodec-ed25519 + raw-public-key)>
func DIDFromKey(pub ed25519.PublicKey) DID {
	prefix := multicodecPrefix(multicodecEd25519)
	buf := make([]byte, 0, len(prefix)+len(pub))
	buf = append(buf, prefix...)
	buf = append(buf, pub...)
	encoded := base58Encode(buf)
	return DID("did:key:z" + encoded)
}

// PublicKey extracts the Ed25519 public key from a did:key DID.
func (d DID) PublicKey() (ed25519.PublicKey, error) {
	s := string(d)
	if !strings.HasPrefix(s, "did:key:z") {
		return nil, errors.New("not a did:key identifier")
	}

	decoded, err := base58Decode(s[len("did:key:z"):])
	if err != nil {
		return nil, fmt.Errorf("decode did:key: %w", err)
	}

	codec, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, errors.New("invalid multicodec varint")
	}
	if codec != multicodecEd25519 {
		return nil, fmt.Errorf("unsupported multicodec: 0x%x", codec)
	}

	pub := decoded[n:]
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(pub), nil
}

// String returns the DID string.
func (d DID) String() string { return string(d) }

// IsZero returns true if the DID is empty.
func (d DID) IsZero() bool { return d == "" }

// Method returns the DID method (e.g., "key" for did:key).
func (d DID) Method() string {
	rest, ok := strings.CutPrefix(string(d), "did:")
	if !ok {
		return ""
	}
	method, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	return method
}

// Document represents a minimal DID Document.
type Document struct {
	ID                 DID                  `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
}

// VerificationMethod describes a public key associated with a DID.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         DID    `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// Resolver resolves a DID to its public key.
type Resolver interface {
	Resolve(ctx context.Context, did DID) (ed25519.PublicKey, error)
}

// KeyResolver resolves did:key DIDs by extracting the embedded public key.
type KeyResolver struct{}

// Resolve extracts the public key from a did:key DID.
func (KeyResolver) Resolve(_ context.Context, did DID) (ed25519.PublicKey, error) {
	if did.Method() != "key" {
		return nil, fmt.Errorf("KeyResolver: unsupported method %q", did.Method())
	}
	return did.PublicKey()
}
