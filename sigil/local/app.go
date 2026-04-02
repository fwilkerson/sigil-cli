// Package local provides application-layer orchestration for the Sigil CLI.
// It wires together identity provisioning, gRPC connectivity, pending
// attestation flush, score caching, and trust client construction — concerns
// that any Sigil transport (CLI, MCP server, etc.) would share.
package local

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/fwilkerson/sigil-cli/sigil/attest"
	sigilgrpc "github.com/fwilkerson/sigil-cli/sigil/grpc"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/local/config"
	"github.com/fwilkerson/sigil-cli/sigil/local/keystore"
	"github.com/fwilkerson/sigil-cli/sigil/local/pending"
	"github.com/fwilkerson/sigil-cli/sigil/local/scorecache"
	"github.com/fwilkerson/sigil-cli/sigil/local/trust"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
)

// App holds the shared state for a Sigil session: config directory, identity,
// and gRPC connection. It exposes orchestration methods that are
// transport-agnostic.
type App struct {
	Dir     string
	KeyPair *signing.KeyPair
	DID     identity.DID

	conn    *grpc.ClientConn
	querier *sigilgrpc.Querier
	client  *trust.Client
}

// CheckOutcome is the result of a trust check, which may come from the live
// service or from the local score cache.
type CheckOutcome struct {
	Live   *trust.CheckResult
	Cached *scorecache.CachedScore
}

// IsCached reports whether the outcome was served from the local cache.
func (o *CheckOutcome) IsCached() bool { return o.Cached != nil }

// New creates an App rooted at dir without a gRPC connection. Use this for
// commands that only need local state (e.g. identity queries).
func New(dir string) *App {
	return &App{Dir: dir}
}

// Connect dials the trust service and returns an App rooted at dir.
func Connect(addr, dir string) (*App, error) {
	conn, err := grpc.NewClient(addr, sigilgrpc.DialOpts()...)
	if err != nil {
		return nil, fmt.Errorf("connect to trust service: %w", err)
	}
	return &App{Dir: dir, conn: conn, querier: sigilgrpc.NewQuerier(conn)}, nil
}

// Close releases the gRPC connection.
func (a *App) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Conn returns the underlying gRPC client connection. Use this for operations
// that need the raw protobuf client (e.g. ListTopTools).
func (a *App) Conn() *grpc.ClientConn { return a.conn }

// LoadIdentityMeta loads identity metadata from the local keystore.
func (a *App) LoadIdentityMeta() (*keystore.IdentityMeta, error) {
	return keystore.LoadIdentityMeta(a.Dir)
}

// LoadIdentity loads the signing key pair and DID from the local keystore.
func (a *App) LoadIdentity() (*signing.KeyPair, identity.DID, error) {
	return keystore.LoadIdentity(a.Dir)
}

// EnsureIdentity loads or creates the auto-identity. On success it populates
// KeyPair and DID and reports whether a new identity was created.
func (a *App) EnsureIdentity() (created bool, err error) {
	kp, did, created, err := keystore.EnsureIdentity(a.Dir)
	if err != nil {
		return false, err
	}
	a.KeyPair = kp
	a.DID = did
	return created, nil
}

// TrustClient returns a [trust.Client] backed by the gRPC connection. The
// client is created lazily and cached for the lifetime of the App.
func (a *App) TrustClient() *trust.Client {
	if a.client == nil {
		a.client = trust.NewClient(a.querier)
	}
	return a.client
}

// LoadConfig loads the Sigil configuration from Dir.
func (a *App) LoadConfig() (*config.Config, error) {
	return config.Load(a.Dir)
}

// FlushPending submits any queued attestations now that gRPC is available.
// Returns the number of successfully submitted attestations. Errors are
// silently ignored — flush is best-effort and should never block the caller.
func (a *App) FlushPending(ctx context.Context) int {
	queue := pending.New(a.Dir)
	plist, err := queue.Pending()
	if err != nil || len(plist) == 0 {
		return 0
	}
	submitted, _, _ := queue.Flush(ctx, a.querier)
	return submitted
}

// EnqueueAttestation writes ta to the pending queue so it can be submitted on
// the next successful connection to the trust service.
func (a *App) EnqueueAttestation(ta *attest.ToolAttestation) error {
	queue := pending.New(a.Dir)
	pa := &pending.Attestation{
		AttestationID: ta.ID.String(),
		AttesterDID:   string(ta.Attester),
		ToolURI:       ta.Tool.String(),
		Outcome:       string(ta.Outcome),
		Claims:        ta.Claims,
		Version:       ta.Version,
		Signature:     ta.Signature,
		IssuedAt:      ta.IssuedAt,
		QueuedAt:      time.Now().UTC(),
	}
	return queue.Enqueue(pa)
}

// Check queries the trust score for a tool, falling back to the local score
// cache when the service is unreachable. On a live hit the result is written
// through to the cache for future offline use.
func (a *App) Check(ctx context.Context, toolURI string) (*CheckOutcome, error) {
	client := a.TrustClient()
	result, err := client.Check(ctx, toolURI)
	if err != nil {
		cache := scorecache.New(a.Dir)
		cached, cacheErr := cache.Get(toolURI)
		if cacheErr != nil || cached == nil {
			return nil, fmt.Errorf("trust service unreachable (no cached data): %w", err)
		}
		return &CheckOutcome{Cached: cached}, nil
	}

	cache := scorecache.New(a.Dir)
	cs := &scorecache.CachedScore{
		ToolURI:          result.ToolURI,
		Score:            result.Score,
		Recommendation:   string(result.Recommendation),
		Label:            result.Label,
		Provisional:      result.Provisional,
		HasData:          result.HasData,
		Attestations:     result.Attestations,
		Attesters:        result.Attesters,
		SuccessRate:      result.SuccessRate,
		VersionsAttested: result.VersionsAttested,
		LatestVersion:    result.LatestVersion,
		CachedAt:         time.Now(),
	}
	_ = cache.Put(toolURI, cs)

	return &CheckOutcome{Live: result}, nil
}
