package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// DIDURL converts a did:web DID to its HTTPS URL per the W3C spec.
//
//	did:web:example.com         → https://example.com/.well-known/did.json
//	did:web:example.com:path:to → https://example.com/path/to/did.json
//
// Percent-encoded characters are decoded. Colons after the method-specific
// identifier become path separators.
func DIDURL(d DID) (string, error) {
	s := string(d)
	if !strings.HasPrefix(s, "did:web:") {
		return "", errors.New("not a did:web identifier")
	}

	specific := s[len("did:web:"):]
	if specific == "" {
		return "", errors.New("empty did:web identifier")
	}

	parts := strings.Split(specific, ":")
	for i, p := range parts {
		decoded, err := url.PathUnescape(p)
		if err != nil {
			return "", fmt.Errorf("decode did:web segment: %w", err)
		}
		parts[i] = decoded
	}

	host := parts[0]
	if err := validateHost(host); err != nil {
		return "", err
	}
	if len(parts) == 1 {
		return "https://" + host + "/.well-known/did.json", nil
	}
	path := strings.Join(parts[1:], "/")
	return "https://" + host + "/" + path + "/did.json", nil
}

// validateHost rejects raw IP addresses and empty hosts in did:web identifiers.
// did:web should use domain names; raw IPs enable SSRF against internal services.
func validateHost(host string) error {
	// Strip port if present (e.g., "example.com:8080" from percent-decoded input).
	h := host
	if i := strings.LastIndex(h, ":"); i != -1 {
		h = h[:i]
	}
	if h == "" {
		return errors.New("empty host in did:web identifier")
	}
	if net.ParseIP(h) != nil {
		return fmt.Errorf("raw IP address not allowed in did:web: %s", h)
	}
	if h == "localhost" {
		return errors.New("localhost not allowed in did:web identifier")
	}
	return nil
}

// NewDocument creates a DID Document with a single Ed25519 verification method.
// The key is encoded as a z-prefixed base58btc multicodec value, consistent
// with the did:key encoding.
func NewDocument(did DID, pub ed25519.PublicKey) *Document {
	encoded := multibaseEncode(pub)
	return &Document{
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 string(did) + "#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         did,
				PublicKeyMultibase: encoded,
			},
		},
	}
}

// multibaseEncode encodes an Ed25519 public key as z-prefixed base58btc
// multicodec, identical to the encoding used in did:key.
func multibaseEncode(pub ed25519.PublicKey) string {
	buf := append(multicodecPrefix(multicodecEd25519), pub...)
	return "z" + base58Encode(buf)
}

// PublicKeyFromDocument extracts the first Ed25519 public key from a Document's
// verificationMethod array. It looks for type "Ed25519VerificationKey2020"
// with a z-prefixed publicKeyMultibase value.
func PublicKeyFromDocument(doc *Document) (ed25519.PublicKey, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.Type != "Ed25519VerificationKey2020" {
			continue
		}
		if !strings.HasPrefix(vm.PublicKeyMultibase, "z") {
			continue
		}

		decoded, err := base58Decode(vm.PublicKeyMultibase[1:])
		if err != nil {
			return nil, fmt.Errorf("decode publicKeyMultibase: %w", err)
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
	return nil, errors.New("no Ed25519VerificationKey2020 method found")
}

// Fetcher retrieves a DID document by URL. The proto package defines the
// contract; callers inject the HTTP implementation.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// WebResolver resolves did:web DIDs via an injected Fetcher.
type WebResolver struct {
	Fetch Fetcher
}

// Resolve computes the HTTPS URL for a did:web DID, fetches the document,
// and extracts the Ed25519 public key.
func (r *WebResolver) Resolve(ctx context.Context, did DID) (ed25519.PublicKey, error) {
	if did.Method() != "web" {
		return nil, fmt.Errorf("WebResolver: unsupported method %q", did.Method())
	}

	u, err := DIDURL(did)
	if err != nil {
		return nil, fmt.Errorf("compute did:web URL: %w", err)
	}

	data, err := r.Fetch(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("fetch did document: %w", err)
	}

	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal did document: %w", err)
	}

	if doc.ID != did {
		return nil, fmt.Errorf("document ID %q does not match requested DID %q", doc.ID, did)
	}

	return PublicKeyFromDocument(&doc)
}
