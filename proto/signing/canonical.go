package signing

import (
	"crypto/ed25519"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Canonicalize produces the RFC 8785 (JCS) canonical form of JSON data.
// This ensures deterministic byte representation for signing and verification.
func Canonicalize(data []byte) ([]byte, error) {
	out, err := jcs.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return out, nil
}

// SignCanonical canonicalizes the JSON data, then signs it.
func SignCanonical(kp *KeyPair, data []byte) ([]byte, error) {
	canonical, err := Canonicalize(data)
	if err != nil {
		return nil, err
	}
	return Sign(kp.Private, canonical), nil
}

// VerifyCanonical canonicalizes the JSON data, then verifies the signature.
func VerifyCanonical(pub ed25519.PublicKey, data, signature []byte) (bool, error) {
	canonical, err := Canonicalize(data)
	if err != nil {
		return false, err
	}
	return Verify(pub, canonical, signature), nil
}
