package identity

import (
	"context"
	"crypto/ed25519"
	"fmt"
)

// CompositeResolver dispatches DID resolution to method-specific resolvers.
// KeyResolver is always registered for "key".
type CompositeResolver struct {
	resolvers map[string]Resolver
}

// CompositeOption configures a CompositeResolver.
type CompositeOption func(*CompositeResolver)

// WithWebResolver adds a WebResolver for "web" DIDs using the given Fetcher.
func WithWebResolver(f Fetcher) CompositeOption {
	return func(r *CompositeResolver) {
		r.resolvers["web"] = &WebResolver{Fetch: f}
	}
}

// NewCompositeResolver creates a CompositeResolver with KeyResolver always
// registered. Additional resolvers can be added via options.
func NewCompositeResolver(opts ...CompositeOption) *CompositeResolver {
	r := &CompositeResolver{
		resolvers: map[string]Resolver{
			"key": KeyResolver{},
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve dispatches to the resolver registered for the DID's method.
func (r *CompositeResolver) Resolve(ctx context.Context, did DID) (ed25519.PublicKey, error) {
	method := did.Method()
	resolver, ok := r.resolvers[method]
	if !ok {
		return nil, fmt.Errorf("unsupported DID method: %q", method)
	}
	return resolver.Resolve(ctx, did)
}
