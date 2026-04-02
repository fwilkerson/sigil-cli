package local

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/attest"
	"github.com/fwilkerson/sigil-cli/sigil/id"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/local/scorecache"
	localtrust "github.com/fwilkerson/sigil-cli/sigil/local/trust"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
	sigiltrust "github.com/fwilkerson/sigil-cli/sigil/trust"
)

// mockQuerier is a test double for sigiltrust.Querier.
type mockQuerier struct {
	trustResult *sigiltrust.ToolTrustResult
	trustErr    error
	submitID    string
	submitDedup bool
	submitErr   error
	submissions []*sigiltrust.AttestationSubmission
}

func (m *mockQuerier) GetToolTrust(_ context.Context, _ string) (*sigiltrust.ToolTrustResult, error) {
	return m.trustResult, m.trustErr
}

func (m *mockQuerier) SubmitAttestation(_ context.Context, req *sigiltrust.AttestationSubmission) (*sigiltrust.SubmitResult, error) {
	m.submissions = append(m.submissions, req)
	if m.submitErr != nil {
		return nil, m.submitErr
	}
	return &sigiltrust.SubmitResult{AttestationID: m.submitID, Deduplicated: m.submitDedup}, nil
}

func (m *mockQuerier) RetractAttestation(_ context.Context, _, _ string, _ []byte) error {
	return nil
}

// newTestApp creates an App with a temp dir and injected querier for testing.
func newTestApp(t *testing.T, q sigiltrust.Querier) *App {
	t.Helper()
	return &App{
		Dir:     t.TempDir(),
		querier: q,
	}
}

// --- New ---

func TestNew(t *testing.T) {
	t.Parallel()
	app := New("/tmp/sigil-test-new")
	if app.Dir != "/tmp/sigil-test-new" {
		t.Errorf("Dir = %q, want %q", app.Dir, "/tmp/sigil-test-new")
	}
	if app.querier != nil {
		t.Error("querier should be nil for local-only App")
	}
}

// --- TrustClient ---

func TestTrustClient_LazyInit(t *testing.T) {
	t.Parallel()
	q := &mockQuerier{}
	app := newTestApp(t, q)

	c1 := app.TrustClient()
	if c1 == nil {
		t.Fatal("TrustClient() returned nil")
	}

	c2 := app.TrustClient()
	if c1 != c2 {
		t.Error("TrustClient() should return the same instance on repeated calls")
	}
}

// --- Check ---

func TestCheck_LiveHit_WritesToCache(t *testing.T) {
	t.Parallel()
	q := &mockQuerier{
		trustResult: &sigiltrust.ToolTrustResult{
			Score:             0.85,
			TotalAttestations: 50,
			UniqueAttesters:   20,
			SuccessRate:       0.9,
			VersionsAttested:  3,
			LatestVersion:     "2.1.0",
		},
	}
	app := newTestApp(t, q)

	outcome, err := app.Check(context.Background(), "mcp://github.com/example/tool")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	if outcome.IsCached() {
		t.Error("outcome should not be cached on live hit")
	}
	if outcome.Live == nil {
		t.Fatal("Live result should not be nil")
	}
	if outcome.Live.Score != 0.85 {
		t.Errorf("Score = %v, want 0.85", outcome.Live.Score)
	}
	if outcome.Live.VersionsAttested != 3 {
		t.Errorf("VersionsAttested = %d, want 3", outcome.Live.VersionsAttested)
	}

	// Verify write-through: the score cache should now contain the entry.
	cache := scorecache.New(app.Dir)
	cached, err := cache.Get("mcp://github.com/example/tool")
	if err != nil {
		t.Fatalf("cache.Get() error: %v", err)
	}
	if cached == nil {
		t.Fatal("cache entry should exist after live hit")
	}
	if cached.Score != 0.85 {
		t.Errorf("cached Score = %v, want 0.85", cached.Score)
	}
}

func TestCheck_ServiceError_FallsBackToCache(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, &mockQuerier{trustErr: errors.New("connection refused")})

	toolURI := "mcp://github.com/example/tool"

	// Pre-populate the score cache.
	cache := scorecache.New(app.Dir)
	cs := &scorecache.CachedScore{
		ToolURI:  toolURI,
		Score:    0.72,
		HasData:  true,
		CachedAt: time.Now(),
	}
	if err := cache.Put(toolURI, cs); err != nil {
		t.Fatalf("cache.Put() error: %v", err)
	}

	outcome, err := app.Check(context.Background(), toolURI)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	if !outcome.IsCached() {
		t.Error("outcome should be cached on service error")
	}
	if outcome.Cached.Score != 0.72 {
		t.Errorf("cached Score = %v, want 0.72", outcome.Cached.Score)
	}
}

func TestCheck_ServiceError_NoCachedData(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, &mockQuerier{trustErr: errors.New("connection refused")})

	_, err := app.Check(context.Background(), "mcp://github.com/example/tool")
	if err == nil {
		t.Fatal("Check() should error when service fails and no cache exists")
	}
}

// --- EnqueueAttestation + FlushPending ---

func TestEnqueueAndFlush(t *testing.T) {
	t.Parallel()
	q := &mockQuerier{submitID: "att-roundtrip"}
	app := newTestApp(t, q)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	toolID, err := id.NewToolID("mcp://github.com/example/tool")
	if err != nil {
		t.Fatal(err)
	}

	ta := &attest.ToolAttestation{
		ID:        id.NewToolAttestationID(),
		Attester:  identity.DIDFromKey(kp.Public),
		Tool:      toolID,
		Outcome:   attest.OutcomeSuccess,
		Claims:    map[string]string{},
		Version:   "1.0.0",
		Signature: []byte("sig"),
		IssuedAt:  time.Now().UTC().Truncate(time.Second),
	}

	if err := app.EnqueueAttestation(ta); err != nil {
		t.Fatalf("EnqueueAttestation() error: %v", err)
	}

	submitted := app.FlushPending(context.Background())
	if submitted != 1 {
		t.Errorf("FlushPending() = %d, want 1", submitted)
	}
	if len(q.submissions) != 1 {
		t.Fatalf("submissions = %d, want 1", len(q.submissions))
	}
	if q.submissions[0].ToolURI != "mcp://github.com/example/tool" {
		t.Errorf("ToolURI = %q, want %q", q.submissions[0].ToolURI, "mcp://github.com/example/tool")
	}
}

func TestFlushPending_EmptyQueue(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, &mockQuerier{})

	submitted := app.FlushPending(context.Background())
	if submitted != 0 {
		t.Errorf("FlushPending() = %d, want 0 for empty queue", submitted)
	}
}

func TestFlushPending_SubmitError_ReturnsZero(t *testing.T) {
	t.Parallel()
	q := &mockQuerier{submitErr: errors.New("service unavailable")}
	app := newTestApp(t, q)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	toolID, err := id.NewToolID("mcp://github.com/example/tool")
	if err != nil {
		t.Fatal(err)
	}

	ta := &attest.ToolAttestation{
		ID:        id.NewToolAttestationID(),
		Attester:  identity.DIDFromKey(kp.Public),
		Tool:      toolID,
		Outcome:   attest.OutcomeSuccess,
		Claims:    map[string]string{},
		Version:   "1.0.0",
		Signature: []byte("sig"),
		IssuedAt:  time.Now().UTC().Truncate(time.Second),
	}

	if err := app.EnqueueAttestation(ta); err != nil {
		t.Fatalf("EnqueueAttestation() error: %v", err)
	}

	submitted := app.FlushPending(context.Background())
	if submitted != 0 {
		t.Errorf("FlushPending() = %d, want 0 when submissions fail", submitted)
	}
}

// --- LoadIdentity / LoadIdentityMeta ---

func TestLoadIdentity_NoKeystore(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, nil)

	_, _, err := app.LoadIdentity()
	if err == nil {
		t.Fatal("LoadIdentity() should error when no keystore exists")
	}
}

func TestLoadIdentityMeta_NoKeystore(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, nil)

	_, err := app.LoadIdentityMeta()
	if err == nil {
		t.Fatal("LoadIdentityMeta() should error when no keystore exists")
	}
}

// --- CheckOutcome ---

func TestCheckOutcome_IsCached(t *testing.T) {
	t.Parallel()

	live := &CheckOutcome{Live: &localtrust.CheckResult{}}
	if live.IsCached() {
		t.Error("IsCached() should be false when Live is set and Cached is nil")
	}

	cached := &CheckOutcome{Cached: &scorecache.CachedScore{Score: 0.5}}
	if !cached.IsCached() {
		t.Error("IsCached() should be true when Cached is set")
	}
}
