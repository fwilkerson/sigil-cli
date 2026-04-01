// Package attest provides a shared signing lifecycle for all attestation types
// in the Sigil protocol. Both party-to-party sigils and single-party tool
// attestations implement the Sealable interface and use [Seal], [Verify], and
// [VerifyWithResolver] for signing and verification.
package attest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
)

// ErrInvalidSignature is returned when signature verification fails.
var ErrInvalidSignature = errors.New("invalid signature")

// Sealable is an attestation that can be signed (sealed) and verified.
// Both [sigil.Sigil] and [ToolAttestation] implement this interface.
type Sealable interface {
	// Validate checks that all required fields are present and valid.
	// Seal calls Validate before signing.
	Validate() error

	// SigningPayload returns the deterministic canonical byte representation
	// used for signing and verification.
	SigningPayload() ([]byte, error)

	// SetSignature stores the computed signature on the attestation.
	SetSignature(sig []byte)

	// GetSignature returns the attestation's signature.
	GetSignature() []byte

	// Signer returns the DID of the entity that signs this attestation.
	// For a Sigil this is the issuer; for a ToolAttestation the attester.
	Signer() identity.DID
}

// Seal validates and signs a Sealable attestation with the given key pair.
//
// It enforces two invariants before signing:
//  1. The attestation passes Validate().
//  2. The DID derived from the key pair matches Signer(), preventing wrong-key
//     bugs that produce attestations which always fail verification.
func Seal(s Sealable, kp *signing.KeyPair) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	signerDID := identity.DIDFromKey(kp.Public)
	if signerDID != s.Signer() {
		return fmt.Errorf("seal: key DID %s does not match signer DID %s", signerDID, s.Signer())
	}
	data, err := s.SigningPayload()
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	sig, err := signing.SignCanonical(kp, data)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	s.SetSignature(sig)
	return nil
}

// Verify checks a Sealable attestation's signature against the given public key.
func Verify(s Sealable, pub ed25519.PublicKey) error {
	data, err := s.SigningPayload()
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	ok, err := signing.VerifyCanonical(pub, data, s.GetSignature())
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyWithResolver resolves the signer's DID to a public key, then verifies
// the attestation's signature.
func VerifyWithResolver(ctx context.Context, s Sealable, r identity.Resolver) error {
	pub, err := r.Resolve(ctx, s.Signer())
	if err != nil {
		return fmt.Errorf("resolve signer: %w", err)
	}
	return Verify(s, pub)
}
