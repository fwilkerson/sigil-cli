package identity_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fwilkerson/sigil-cli/proto/identity"
)

func TestDIDURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		did     identity.DID
		want    string
		wantErr bool
	}{
		{
			name: "domain only",
			did:  "did:web:example.com",
			want: "https://example.com/.well-known/did.json",
		},
		{
			name: "with path",
			did:  "did:web:example.com:path:to",
			want: "https://example.com/path/to/did.json",
		},
		{
			name: "percent-encoded port",
			did:  "did:web:example.com%3A8080",
			want: "https://example.com:8080/.well-known/did.json",
		},
		{
			name: "with path and port",
			did:  "did:web:example.com%3A8080:dids:abc",
			want: "https://example.com:8080/dids/abc/did.json",
		},
		{
			name:    "not did:web",
			did:     "did:key:z6Mk...",
			wantErr: true,
		},
		{
			name:    "empty identifier",
			did:     "did:web:",
			wantErr: true,
		},
		{
			name:    "reject localhost",
			did:     "did:web:localhost",
			wantErr: true,
		},
		{
			name:    "reject loopback IP",
			did:     "did:web:127.0.0.1",
			wantErr: true,
		},
		{
			name:    "reject private IP 10.x",
			did:     "did:web:10.0.0.1",
			wantErr: true,
		},
		{
			name:    "reject private IP 192.168.x",
			did:     "did:web:192.168.1.1",
			wantErr: true,
		},
		{
			name:    "reject metadata endpoint",
			did:     "did:web:169.254.169.254",
			wantErr: true,
		},
		{
			name:    "reject IPv6 loopback",
			did:     "did:web:::1",
			wantErr: true,
		},
		{
			name: "allow valid domain",
			did:  "did:web:example.com",
			want: "https://example.com/.well-known/did.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := identity.DIDURL(tt.did)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("DIDURL(%q) = %q, want %q", tt.did, got, tt.want)
			}
		})
	}
}

func TestNewDocument_RoundTrip(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)
	did := identity.DID("did:web:example.com")

	doc := identity.NewDocument(did, pub)

	if doc.ID != did {
		t.Fatalf("doc.ID = %q, want %q", doc.ID, did)
	}
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 verification method, got %d", len(doc.VerificationMethod))
	}
	if doc.VerificationMethod[0].Type != "Ed25519VerificationKey2020" {
		t.Fatalf("unexpected type: %s", doc.VerificationMethod[0].Type)
	}

	recovered, err := identity.PublicKeyFromDocument(doc)
	if err != nil {
		t.Fatalf("extract key: %v", err)
	}
	if !pub.Equal(recovered) {
		t.Fatal("round-trip public key mismatch")
	}
}

func TestPublicKeyFromDocument(t *testing.T) {
	t.Parallel()

	t.Run("valid Ed25519", func(t *testing.T) {
		t.Parallel()
		pub := mustGenKey(t)
		doc := identity.NewDocument("did:web:example.com", pub)

		got, err := identity.PublicKeyFromDocument(doc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !pub.Equal(got) {
			t.Fatal("key mismatch")
		}
	})

	t.Run("no methods", func(t *testing.T) {
		t.Parallel()
		doc := &identity.Document{ID: "did:web:example.com"}
		_, err := identity.PublicKeyFromDocument(doc)
		if err == nil {
			t.Fatal("expected error for empty methods")
		}
	})

	t.Run("wrong type skipped", func(t *testing.T) {
		t.Parallel()
		doc := &identity.Document{
			ID: "did:web:example.com",
			VerificationMethod: []identity.VerificationMethod{
				{
					ID:                 "did:web:example.com#key-1",
					Type:               "X25519KeyAgreementKey2020",
					PublicKeyMultibase: "zNotAnEd25519Key",
				},
			},
		}
		_, err := identity.PublicKeyFromDocument(doc)
		if err == nil {
			t.Fatal("expected error for no matching method")
		}
	})
}

func TestWebResolver(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		pub := mustGenKey(t)
		did := identity.DID("did:web:example.com")
		doc := identity.NewDocument(did, pub)
		docJSON, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}

		r := &identity.WebResolver{
			Fetch: func(_ context.Context, url string) ([]byte, error) {
				if url != "https://example.com/.well-known/did.json" {
					t.Fatalf("unexpected URL: %s", url)
				}
				return docJSON, nil
			},
		}

		got, err := r.Resolve(context.Background(), did)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !pub.Equal(got) {
			t.Fatal("resolved key mismatch")
		}
	})

	t.Run("DID mismatch", func(t *testing.T) {
		t.Parallel()
		pub := mustGenKey(t)
		wrongDID := identity.DID("did:web:wrong.com")
		doc := identity.NewDocument(wrongDID, pub)
		docJSON, _ := json.Marshal(doc)

		r := &identity.WebResolver{
			Fetch: func(_ context.Context, _ string) ([]byte, error) {
				return docJSON, nil
			},
		}

		_, err := r.Resolve(context.Background(), identity.DID("did:web:example.com"))
		if err == nil {
			t.Fatal("expected error for DID mismatch")
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		t.Parallel()
		r := &identity.WebResolver{
			Fetch: func(_ context.Context, _ string) ([]byte, error) {
				return nil, nil
			},
		}

		_, err := r.Resolve(context.Background(), identity.DID("did:key:z6Mk..."))
		if err == nil {
			t.Fatal("expected error for wrong method")
		}
	})

	t.Run("no matching verification method", func(t *testing.T) {
		t.Parallel()
		did := identity.DID("did:web:example.com")
		doc := &identity.Document{
			ID: did,
			VerificationMethod: []identity.VerificationMethod{
				{Type: "SomeOtherKeyType", PublicKeyMultibase: "z..."},
			},
		}
		docJSON, _ := json.Marshal(doc)

		r := &identity.WebResolver{
			Fetch: func(_ context.Context, _ string) ([]byte, error) {
				return docJSON, nil
			},
		}

		_, err := r.Resolve(context.Background(), did)
		if err == nil {
			t.Fatal("expected error for no matching method")
		}
	})

	t.Run("SSRF rejected", func(t *testing.T) {
		t.Parallel()
		r := &identity.WebResolver{
			Fetch: func(_ context.Context, _ string) ([]byte, error) {
				t.Fatal("fetch should not be called for rejected host")
				return nil, nil
			},
		}
		_, err := r.Resolve(context.Background(), identity.DID("did:web:127.0.0.1"))
		if err == nil {
			t.Fatal("expected error for SSRF attempt")
		}
	})
}

func TestPublicKeyFromDocument_MultipleEd25519Methods(t *testing.T) {
	t.Parallel()
	// PublicKeyFromDocument iterates verificationMethod in order and returns
	// the first Ed25519VerificationKey2020 entry. When two such entries exist,
	// the key from the first entry must be returned.
	pub1 := mustGenKey(t)
	pub2 := mustGenKey(t)
	did := identity.DID("did:web:example.com")

	doc1 := identity.NewDocument(did, pub1)
	doc2 := identity.NewDocument(did, pub2)

	// Build a document that has both verification methods.
	combined := &identity.Document{
		ID: did,
		VerificationMethod: []identity.VerificationMethod{
			doc1.VerificationMethod[0],
			doc2.VerificationMethod[0],
		},
	}

	got, err := identity.PublicKeyFromDocument(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pub1.Equal(got) {
		t.Fatal("expected first verification method key to be returned")
	}
}

func TestPublicKeyFromDocument_InvalidMultibasePrefix(t *testing.T) {
	t.Parallel()
	// A PublicKeyMultibase value that does not start with "z" (base58btc
	// multibase prefix) must be skipped. If it is the only method the
	// function must return an error.
	doc := &identity.Document{
		ID: "did:web:example.com",
		VerificationMethod: []identity.VerificationMethod{
			{
				ID:                 "did:web:example.com#key-1",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:web:example.com",
				PublicKeyMultibase: "mSomeBase64EncodedKey", // "m" = base64 multibase prefix
			},
		},
	}
	_, err := identity.PublicKeyFromDocument(doc)
	if err == nil {
		t.Fatal("expected error for non-z multibase prefix")
	}
}

func TestWebResolver_FetchError(t *testing.T) {
	t.Parallel()
	// When the Fetcher returns an error, WebResolver.Resolve must propagate it.
	fetchErr := errors.New("network unreachable")
	r := &identity.WebResolver{
		Fetch: func(_ context.Context, _ string) ([]byte, error) {
			return nil, fetchErr
		},
	}

	_, err := r.Resolve(context.Background(), identity.DID("did:web:example.com"))
	if err == nil {
		t.Fatal("expected error when fetcher fails")
	}
	if !errors.Is(err, fetchErr) {
		t.Fatalf("error chain should contain fetchErr; got %v", err)
	}
}

func TestNewDocument_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := identity.DID("did:web:example.com:dids:abc123")

	doc := identity.NewDocument(did, pub)

	// Marshal and unmarshal to verify JSON serialization works.
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc2 identity.Document
	if err := json.Unmarshal(data, &doc2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	recovered, err := identity.PublicKeyFromDocument(&doc2)
	if err != nil {
		t.Fatalf("extract from unmarshaled: %v", err)
	}
	if !pub.Equal(recovered) {
		t.Fatal("JSON round-trip key mismatch")
	}
}
