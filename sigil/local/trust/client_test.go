package trust

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
	sigiltrust "github.com/fwilkerson/sigil-cli/sigil/trust"
)

// mockQuerier is a test double for trust.Querier.
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

func (m *mockQuerier) RetractAttestation(_ context.Context, attestationID, _ string, _ []byte) error {
	if m.submitErr != nil {
		return m.submitErr
	}
	m.submitID = attestationID
	return nil
}

func (m *mockQuerier) SubmitAttestation(_ context.Context, req *sigiltrust.AttestationSubmission) (*sigiltrust.SubmitResult, error) {
	m.submissions = append(m.submissions, req)
	if m.submitErr != nil {
		return nil, m.submitErr
	}
	return &sigiltrust.SubmitResult{AttestationID: m.submitID, Deduplicated: m.submitDedup}, nil
}

func TestClient_Check(t *testing.T) {
	q := &mockQuerier{
		trustResult: &sigiltrust.ToolTrustResult{
			Score:             0.85,
			TotalAttestations: 50,
			UniqueAttesters:   20,
			SuccessRate:       0.9,
		},
	}
	c := NewClient(q)

	result, err := c.Check(context.Background(), "mcp://github.com/example/tool")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	if result.Recommendation != RecommendUse {
		t.Errorf("Recommendation = %q, want %q", result.Recommendation, RecommendUse)
	}
	if !result.HasData {
		t.Error("HasData should be true")
	}
	if result.Score != 0.85 {
		t.Errorf("Score = %v, want 0.85", result.Score)
	}
}

func TestClient_Check_WithVersions(t *testing.T) {
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
	c := NewClient(q)

	result, err := c.Check(context.Background(), "mcp://github.com/example/tool")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	if result.VersionsAttested != 3 {
		t.Errorf("VersionsAttested = %d, want 3", result.VersionsAttested)
	}
	if result.LatestVersion != "2.1.0" {
		t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, "2.1.0")
	}
}

func TestClient_Check_Unknown(t *testing.T) {
	q := &mockQuerier{
		trustResult: &sigiltrust.ToolTrustResult{
			Score:             0,
			TotalAttestations: 0,
		},
	}
	c := NewClient(q)

	result, err := c.Check(context.Background(), "mcp://github.com/example/tool")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	if result.Recommendation != RecommendUnknown {
		t.Errorf("Recommendation = %q, want %q", result.Recommendation, RecommendUnknown)
	}
	if result.HasData {
		t.Error("HasData should be false")
	}
}

func TestClient_Check_InvalidURI(t *testing.T) {
	c := NewClient(&mockQuerier{})

	_, err := c.Check(context.Background(), "not-a-valid-uri")
	if err == nil {
		t.Fatal("Check() should error on invalid URI")
	}
}

func TestClient_Check_QuerierError(t *testing.T) {
	q := &mockQuerier{trustErr: errors.New("connection refused")}
	c := NewClient(q)

	_, err := c.Check(context.Background(), "mcp://github.com/example/tool")
	if err == nil {
		t.Fatal("Check() should propagate querier errors")
	}
}

func TestClient_AttestPositive(t *testing.T) {
	q := &mockQuerier{submitID: "att-123"}
	c := NewClient(q)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.AttestPositive(context.Background(), "mcp://github.com/example/tool", "1.0.0", kp)
	if err != nil {
		t.Fatalf("AttestPositive() error: %v", err)
	}
	if res == nil {
		t.Fatal("AttestPositive() returned nil result")
	}
	if res.AttestationID != "att-123" {
		t.Errorf("ID = %q, want %q", res.AttestationID, "att-123")
	}
	if len(q.submissions) != 1 {
		t.Fatalf("submissions = %d, want 1", len(q.submissions))
	}
	sub := q.submissions[0]
	if sub.Outcome != "success" {
		t.Errorf("Outcome = %q, want %q", sub.Outcome, "success")
	}
	if len(sub.Signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestClient_AttestPositive_RateLimited(t *testing.T) {
	q := &mockQuerier{submitID: "att-123"}
	c := NewClient(q)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	toolURI := "mcp://github.com/example/tool"

	// First call succeeds.
	res, err := c.AttestPositive(context.Background(), toolURI, "1.0.0", kp)
	if err != nil {
		t.Fatalf("first AttestPositive() error: %v", err)
	}
	if res == nil {
		t.Error("first call should return a result")
	}

	// Second call is rate-limited.
	res, err = c.AttestPositive(context.Background(), toolURI, "1.0.0", kp)
	if err != nil {
		t.Fatalf("second AttestPositive() error: %v", err)
	}
	if res != nil {
		t.Error("second call should return nil (rate-limited)")
	}
	if len(q.submissions) != 1 {
		t.Errorf("submissions = %d, want 1 (second should be skipped)", len(q.submissions))
	}
}

func TestClient_PrepareAndSubmitNegative(t *testing.T) {
	q := &mockQuerier{submitID: "neg-456"}
	c := NewClient(q)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]string{
		"intent":     "list files",
		"result":     "permission denied",
		"error_code": "EPERM",
	}

	// Step 1: prepare (no signing yet).
	ta, err := c.PrepareNegative("mcp://github.com/example/tool", "2.0.0", claims, kp)
	if err != nil {
		t.Fatalf("PrepareNegative() error: %v", err)
	}
	if len(ta.Signature) != 0 {
		t.Error("prepared attestation should not be signed yet")
	}
	if ta.Outcome != "negative" {
		t.Errorf("Outcome = %q, want %q", ta.Outcome, "negative")
	}

	// Step 2: user reviews, then submit.
	res, err := c.SubmitPrepared(context.Background(), ta, kp)
	if err != nil {
		t.Fatalf("SubmitPrepared() error: %v", err)
	}
	if res == nil {
		t.Fatal("SubmitPrepared() returned nil result")
	}
	if res.AttestationID != "neg-456" {
		t.Errorf("ID = %q, want %q", res.AttestationID, "neg-456")
	}
	if len(ta.Signature) == 0 {
		t.Error("attestation should be signed after submit")
	}
}

func TestClient_PrepareNegative_InvalidURI(t *testing.T) {
	c := NewClient(&mockQuerier{})
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.PrepareNegative("bad-uri", "1.0", nil, kp)
	if err == nil {
		t.Fatal("PrepareNegative() should error on invalid URI")
	}
}

func TestClient_WithCooldownLimiter(t *testing.T) {
	q := &mockQuerier{submitID: "att-1"}
	limiter := NewSessionLimiter(24 * time.Hour)
	c := NewClientWithLimiter(q, limiter)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AttestPositive(context.Background(), "mcp://github.com/example/tool", "1.0", kp)
	if err != nil {
		t.Fatal(err)
	}

	// Second call within 24h is rate-limited.
	res, err := c.AttestPositive(context.Background(), "mcp://github.com/example/tool", "1.0", kp)
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Error("should be rate-limited within cooldown")
	}
}

func TestClient_Retract(t *testing.T) {
	t.Parallel()
	q := &mockQuerier{}
	c := NewClient(q)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	did := identity.DIDFromKey(kp.Public)
	if err := c.Retract(context.Background(), "att-123", did, kp); err != nil {
		t.Fatalf("Retract() error: %v", err)
	}
	if q.submitID != "att-123" {
		t.Errorf("submitID = %q, want %q", q.submitID, "att-123")
	}
}

func TestClient_Retract_Error(t *testing.T) {
	t.Parallel()
	q := &mockQuerier{submitErr: errors.New("not found")}
	c := NewClient(q)

	kp, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	did := identity.DIDFromKey(kp.Public)
	if err := c.Retract(context.Background(), "att-123", did, kp); err == nil {
		t.Fatal("Retract() should propagate querier errors")
	}
}
