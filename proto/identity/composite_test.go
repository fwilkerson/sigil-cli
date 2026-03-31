package identity_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fwilkerson/sigil-cli/proto/identity"
)

func TestCompositeResolver_DidKey(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)
	did := identity.DIDFromKey(pub)

	r := identity.NewCompositeResolver()
	got, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("resolve did:key: %v", err)
	}
	if !pub.Equal(got) {
		t.Fatal("resolved key mismatch")
	}
}

func TestCompositeResolver_DidWeb(t *testing.T) {
	t.Parallel()
	pub := mustGenKey(t)
	did := identity.DID("did:web:example.com")
	doc := identity.NewDocument(did, pub)
	docJSON, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	r := identity.NewCompositeResolver(
		identity.WithWebResolver(func(_ context.Context, _ string) ([]byte, error) {
			return docJSON, nil
		}),
	)

	got, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("resolve did:web: %v", err)
	}
	if !pub.Equal(got) {
		t.Fatal("resolved key mismatch")
	}
}

func TestCompositeResolver_UnsupportedMethod(t *testing.T) {
	t.Parallel()
	r := identity.NewCompositeResolver()
	_, err := r.Resolve(context.Background(), identity.DID("did:example:123"))
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

func TestCompositeResolver_DidWeb_WithoutOption(t *testing.T) {
	t.Parallel()
	r := identity.NewCompositeResolver()
	_, err := r.Resolve(context.Background(), identity.DID("did:web:example.com"))
	if err == nil {
		t.Fatal("expected error for did:web without WithWebResolver")
	}
}

// blockingFetcher is a Fetcher that blocks until the context is cancelled,
// then returns the context's error.
func blockingFetcher(ctx context.Context, _ string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCompositeResolver_CancelledContext(t *testing.T) {
	t.Parallel()

	r := identity.NewCompositeResolver(
		identity.WithWebResolver(blockingFetcher),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling Resolve

	_, err := r.Resolve(ctx, identity.DID("did:web:example.com"))
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestCompositeResolver_DeadlineExceeded(t *testing.T) {
	t.Parallel()

	r := identity.NewCompositeResolver(
		identity.WithWebResolver(blockingFetcher),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	_, err := r.Resolve(ctx, identity.DID("did:web:example.com"))
	if err == nil {
		t.Fatal("expected error for deadline-exceeded context")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
}
