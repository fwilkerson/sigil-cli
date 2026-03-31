package toolattest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/fwilkerson/sigil-cli/proto/id"
	"github.com/fwilkerson/sigil-cli/proto/identity"
)

// Sentinel errors returned by Store implementations.
var (
	// ErrNotFound is returned by Get when no attestation matches the given ID.
	ErrNotFound = errors.New("attestation not found")

	// ErrAlreadyExists is returned by Put when an attestation with the same ID
	// and identical content already exists. This is the expected result for
	// idempotent client retries and does not indicate a problem.
	ErrAlreadyExists = errors.New("attestation already exists")

	// ErrConflict is returned by Put when an attestation with the same ID but
	// different content arrives. This signals potential tampering or a client
	// bug — the caller should treat this as an error condition.
	ErrConflict = errors.New("attestation ID conflict: content mismatch")
)

// Store persists and queries ToolAttestations.
//
// # Idempotency
//
// Put enforces content-addressable idempotency: if an attestation with the
// same ID already exists and has identical content, Put returns ErrAlreadyExists.
// If the same ID arrives with different content, Put returns ErrConflict to
// signal potential tampering or a client bug. This prevents client retries from
// inflating trust scores and blocks ID pre-computation attacks.
//
// # Signature verification
//
// Signature verification is the caller's responsibility. The gRPC handler in
// task 005 verifies before calling Put. Store implementations must not verify
// signatures — this is consistent with the rest of the codebase (sigil.Verify
// is never called by storage layers).
//
// # Right-to-delete
//
// Future implementations must support attestation deletion (right-to-delete,
// Phase 6) without breaking referential integrity. Concrete backends should use
// soft-delete columns or ensure hard deletes cannot cascade to break trust
// score computation. This does not need to be implemented now, but the schema
// must not prevent it.
type Store interface {
	// Put inserts a new attestation. See idempotency rules in the Store godoc.
	Put(ctx context.Context, att *ToolAttestation) error

	// Get retrieves a single attestation by ID.
	// Returns ErrNotFound if no attestation with that ID exists.
	Get(ctx context.Context, id id.ToolAttestationID) (*ToolAttestation, error)

	// ListByTool returns attestations for the given tool, ordered by ID
	// (chronological). limit controls the page size (0 uses a default).
	// pageToken is the last-seen ToolAttestationID from a prior call; pass
	// empty string for the first page. Returns the next page token, which is
	// empty when there are no further results.
	ListByTool(ctx context.Context, toolID id.ToolID, limit int, pageToken string) ([]ToolAttestation, string, error)

	// ListByToolSince returns attestations for the given tool issued at or
	// after since, ordered by ID. It supports cursor-based pagination
	// identical to ListByTool. This is used for time-windowed trust scoring
	// ("attestations since last compaction point"). Because a tool may
	// accumulate thousands of attestations in a single window, pagination
	// is required.
	ListByToolSince(ctx context.Context, toolID id.ToolID, since time.Time, limit int, pageToken string) ([]ToolAttestation, string, error)

	// ListByAttester returns attestations issued by the given attester, ordered
	// by ID. It supports cursor-based pagination identical to ListByTool.
	//
	// Privacy note: although DIDs contain no inherent PII, tool usage patterns
	// are quasi-identifiers that can potentially be correlated with external
	// data. This query exposes an attester's full attestation history. It is
	// used internally for attester reputation computation (task 006) and MUST
	// NOT be exposed publicly without additional privacy controls such as
	// rate-limiting, access-token scoping, or differential privacy aggregation.
	ListByAttester(ctx context.Context, attester identity.DID, limit int, pageToken string) ([]ToolAttestation, string, error)

	// ListOlderThan returns attestations with IssuedAt before the given
	// threshold, across all tools, ordered by ID. It supports cursor-based
	// pagination identical to ListByTool. This is used for compaction:
	// iterating all stale attestations without O(tools) calls to
	// ListByToolSince.
	ListOlderThan(ctx context.Context, before time.Time, limit int, pageToken string) ([]ToolAttestation, string, error)
}

const defaultPageSize = 50

// MemStore is an in-memory implementation of Store for use in tests.
// It is not suitable for production use.
//
// MemStore is safe for concurrent use.
type MemStore struct {
	mu   sync.RWMutex
	data []ToolAttestation // ordered by insertion (ULID order for Put)
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{} }

// Put inserts att into the store. See Store.Put for idempotency rules.
func (m *MemStore) Put(_ context.Context, att *ToolAttestation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.data {
		if m.data[i].ID == att.ID {
			if contentEqual(&m.data[i], att) {
				return ErrAlreadyExists
			}
			return ErrConflict
		}
	}
	// Append a copy to avoid the caller mutating stored state.
	cp := copyAttestation(att)
	m.data = append(m.data, cp)
	return nil
}

// Get returns the attestation with the given ID, or ErrNotFound.
func (m *MemStore) Get(_ context.Context, attID id.ToolAttestationID) (*ToolAttestation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for i := range m.data {
		if m.data[i].ID == attID {
			cp := m.data[i]
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// ListByTool implements Store.ListByTool.
func (m *MemStore) ListByTool(_ context.Context, toolID id.ToolID, limit int, pageToken string) ([]ToolAttestation, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return paginate(m.data, limit, pageToken, func(a *ToolAttestation) bool {
		return a.Tool == toolID
	})
}

// ListByToolSince implements Store.ListByToolSince.
func (m *MemStore) ListByToolSince(_ context.Context, toolID id.ToolID, since time.Time, limit int, pageToken string) ([]ToolAttestation, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return paginate(m.data, limit, pageToken, func(a *ToolAttestation) bool {
		return a.Tool == toolID && !a.IssuedAt.Before(since)
	})
}

// ListByAttester implements Store.ListByAttester.
//
// See privacy note on Store.ListByAttester.
func (m *MemStore) ListByAttester(_ context.Context, attester identity.DID, limit int, pageToken string) ([]ToolAttestation, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return paginate(m.data, limit, pageToken, func(a *ToolAttestation) bool {
		return a.Attester == attester
	})
}

// ListOlderThan implements Store.ListOlderThan.
func (m *MemStore) ListOlderThan(_ context.Context, before time.Time, limit int, pageToken string) ([]ToolAttestation, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return paginate(m.data, limit, pageToken, func(a *ToolAttestation) bool {
		return a.IssuedAt.Before(before)
	})
}

// paginate filters data by predicate and returns at most limit items starting
// after pageToken (last-seen ID string). It returns the next page token, which
// is empty when there are no further results.
func paginate(data []ToolAttestation, limit int, pageToken string, match func(*ToolAttestation) bool) ([]ToolAttestation, string, error) {
	if limit <= 0 {
		limit = defaultPageSize
	}

	// Collect matching entries in order, skipping those at or before the cursor.
	pastCursor := pageToken == ""
	var results []ToolAttestation
	for i := range data {
		a := &data[i]
		if !pastCursor {
			if a.ID.String() == pageToken {
				pastCursor = true
			}
			continue
		}
		if match(a) {
			cp := copyAttestation(a)
			results = append(results, cp)
		}
	}

	var nextToken string
	if len(results) > limit {
		results = results[:limit]
		nextToken = results[limit-1].ID.String()
	}

	return results, nextToken, nil
}

// contentEqual returns true when two attestations have identical content
// (all fields except pointer identity).
func contentEqual(a, b *ToolAttestation) bool {
	if a.ID != b.ID ||
		a.Attester != b.Attester ||
		a.Tool != b.Tool ||
		a.Outcome != b.Outcome ||
		a.Version != b.Version ||
		!a.IssuedAt.Equal(b.IssuedAt) ||
		!bytes.Equal(a.Signature, b.Signature) {
		return false
	}
	if len(a.Claims) != len(b.Claims) {
		return false
	}
	for k, v := range a.Claims {
		if b.Claims[k] != v {
			return false
		}
	}
	return true
}

// copyAttestation returns a shallow copy of att with the Claims map deep-copied.
func copyAttestation(att *ToolAttestation) ToolAttestation {
	cp := *att
	if att.Claims != nil {
		cp.Claims = make(map[string]string, len(att.Claims))
		for k, v := range att.Claims {
			cp.Claims[k] = v
		}
	}
	if att.Signature != nil {
		cp.Signature = make([]byte, len(att.Signature))
		copy(cp.Signature, att.Signature)
	}
	return cp
}

// Compile-time check that *MemStore implements Store.
var _ Store = (*MemStore)(nil)
