// Package signing provides Ed25519 key management, signing, verification,
// and BIP-39 mnemonic backup for the Sigil protocol.
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

// KeyPair holds an Ed25519 signing key and its corresponding public key.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKeyPair creates a new random Ed25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv}, nil
}

// GenerateKeyPairWithMnemonic creates a new key pair and returns a 12-word
// BIP-39 mnemonic that can deterministically regenerate it.
func GenerateKeyPairWithMnemonic() (*KeyPair, string, error) {
	entropy, err := bip39.NewEntropy(128) // 128 bits → 12 words
	if err != nil {
		return nil, "", fmt.Errorf("generate entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, "", fmt.Errorf("generate mnemonic: %w", err)
	}
	kp := keyPairFromMnemonic(mnemonic)
	return kp, mnemonic, nil
}

// KeyPairFromMnemonic deterministically derives an Ed25519 key pair from
// a BIP-39 mnemonic phrase.
func KeyPairFromMnemonic(mnemonic string) (*KeyPair, error) {
	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic")
	}
	return keyPairFromMnemonic(mnemonic), nil
}

func keyPairFromMnemonic(mnemonic string) *KeyPair {
	// Derive a 32-byte seed from the mnemonic via SHA-256 of the BIP-39 seed.
	// BIP-39 seed uses empty passphrase for simplicity.
	bip39Seed := bip39.NewSeed(mnemonic, "")
	hash := sha256.Sum256(bip39Seed)
	priv := ed25519.NewKeyFromSeed(hash[:])
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{Public: pub, Private: priv}
}

// Sign produces an Ed25519 signature over the given message.
func Sign(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// Verify checks an Ed25519 signature against a public key and message.
func Verify(pub ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pub, message, signature)
}
