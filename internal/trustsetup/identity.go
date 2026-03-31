package trustsetup

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fwilkerson/sigil-cli/internal/fsutil"
	"github.com/fwilkerson/sigil-cli/proto/identity"
	"github.com/fwilkerson/sigil-cli/proto/signing"
)

const autoIdentityName = "auto"

// IdentityMeta holds metadata for a stored identity.
type IdentityMeta struct {
	Name      string       `json:"name"`
	DID       identity.DID `json:"did"`
	CreatedAt time.Time    `json:"created_at"`
}

// EnsureIdentity loads or creates the auto-generated identity. On first use
// it generates a did:key identity and stores it in the config directory.
// Returns the keypair, DID, and whether a new identity was created.
func EnsureIdentity(configDir string) (*signing.KeyPair, identity.DID, bool, error) {
	idDir := filepath.Join(configDir, "identities", autoIdentityName)

	kp, did, err := loadIdentity(idDir)
	if err == nil {
		return kp, did, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, "", false, fmt.Errorf("load identity: %w", err)
	}

	kp, err = signing.GenerateKeyPair()
	if err != nil {
		return nil, "", false, fmt.Errorf("generate keypair: %w", err)
	}
	did = identity.DIDFromKey(kp.Public)

	if err := saveIdentity(idDir, kp, did); err != nil {
		return nil, "", false, err
	}

	return kp, did, true, nil
}

// LoadIdentity loads the stored identity without creating one.
func LoadIdentity(configDir string) (*signing.KeyPair, identity.DID, error) {
	idDir := filepath.Join(configDir, "identities", autoIdentityName)
	kp, did, err := loadIdentity(idDir)
	if err != nil {
		return nil, "", fmt.Errorf("load identity: %w", err)
	}
	return kp, did, nil
}

// LoadIdentityMeta loads the identity metadata without loading the private key.
// Returns os.ErrNotExist if no identity exists.
func LoadIdentityMeta(configDir string) (*IdentityMeta, error) {
	idDir := filepath.Join(configDir, "identities", autoIdentityName)
	data, err := os.ReadFile(filepath.Join(idDir, "identity.json"))
	if err != nil {
		return nil, err
	}
	var meta IdentityMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse identity metadata: %w", err)
	}
	return &meta, nil
}

func loadIdentity(idDir string) (*signing.KeyPair, identity.DID, error) {
	seed, err := os.ReadFile(filepath.Join(idDir, "private.key"))
	if err != nil {
		return nil, "", err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, "", fmt.Errorf("private key file is corrupt (expected %d bytes, got %d)", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	kp := &signing.KeyPair{Public: pub, Private: priv}
	return kp, identity.DIDFromKey(pub), nil
}

func saveIdentity(idDir string, kp *signing.KeyPair, did identity.DID) error {
	if err := os.MkdirAll(idDir, 0o700); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
	}

	seed := kp.Private.Seed()
	if err := fsutil.WriteFileAtomic(filepath.Join(idDir, "private.key"), seed, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	if err := fsutil.WriteFileAtomic(filepath.Join(idDir, "public.key"), []byte(kp.Public), 0o600); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	meta := &IdentityMeta{
		Name:      autoIdentityName,
		DID:       did,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(idDir, "identity.json"), data, 0o600); err != nil {
		return fmt.Errorf("write identity metadata: %w", err)
	}

	return nil
}
