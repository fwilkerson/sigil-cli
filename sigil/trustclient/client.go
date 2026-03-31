package trustclient

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/attest"
	"github.com/fwilkerson/sigil-cli/sigil/id"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
	"github.com/fwilkerson/sigil-cli/sigil/signing"
	"github.com/fwilkerson/sigil-cli/sigil/toolattest"
)

// TrustQuerier abstracts the trust service backend. Implementations may use
// gRPC, the CLI, or an in-memory stub for testing.
type TrustQuerier interface {
	// GetToolTrust returns the trust digest for a tool URI.
	GetToolTrust(ctx context.Context, toolURI string) (*ToolTrustResult, error)

	// SubmitAttestation submits a signed attestation and returns the result.
	SubmitAttestation(ctx context.Context, req *AttestationSubmission) (*SubmitResult, error)

	// RetractAttestation soft-deletes an attestation with a signed deletion proof.
	RetractAttestation(ctx context.Context, attestationID, attesterDID string, signature []byte) error
}

// SubmitResult is the outcome of submitting an attestation.
type SubmitResult struct {
	AttestationID string
	Deduplicated  bool
}

// ToolTrustResult is the response from a trust query.
type ToolTrustResult struct {
	Score             float64
	TotalAttestations int
	UniqueAttesters   int
	SuccessRate       float64
	Provisional       bool
	FirstSeen         time.Time
	LastActive        time.Time
	VersionsAttested  int
	LatestVersion     string
}

// AttestationSubmission carries a signed attestation to the backend.
type AttestationSubmission struct {
	AttestationID string
	AttesterDID   string
	ToolURI       string
	Outcome       string
	Claims        map[string]string
	Version       string
	Signature     []byte
	IssuedAt      time.Time
}

// CheckResult is the outcome of a trust check for a tool.
type CheckResult struct {
	ToolURI          string
	Score            float64
	Recommendation   Recommendation
	Label            string
	Provisional      bool
	HasData          bool
	Attestations     int
	Attesters        int
	SuccessRate      float64
	VersionsAttested int
	LatestVersion    string
}

// Client wraps a [TrustQuerier] with recommendation logic and rate limiting.
type Client struct {
	querier TrustQuerier
	limiter *SessionLimiter
}

// NewClient creates a trust client with the given backend and a default
// session limiter (once per tool per session).
func NewClient(q TrustQuerier) *Client {
	return &Client{
		querier: q,
		limiter: NewSessionLimiter(0),
	}
}

// NewClientWithLimiter creates a trust client with a custom rate limiter.
func NewClientWithLimiter(q TrustQuerier, limiter *SessionLimiter) *Client {
	return &Client{
		querier: q,
		limiter: limiter,
	}
}

// Check queries the trust score for a tool and returns a recommendation.
func (c *Client) Check(ctx context.Context, toolURI string) (*CheckResult, error) {
	// Validate tool URI.
	if _, err := id.NewToolID(toolURI); err != nil {
		return nil, fmt.Errorf("invalid tool URI: %w", err)
	}

	result, err := c.querier.GetToolTrust(ctx, toolURI)
	if err != nil {
		return nil, fmt.Errorf("query trust: %w", err)
	}

	rec, label := Recommend(result.Score, result.TotalAttestations, result.Provisional)

	return &CheckResult{
		ToolURI:          toolURI,
		Score:            result.Score,
		Recommendation:   rec,
		Label:            label,
		Provisional:      result.Provisional,
		HasData:          result.TotalAttestations > 0,
		Attestations:     result.TotalAttestations,
		Attesters:        result.UniqueAttesters,
		SuccessRate:      result.SuccessRate,
		VersionsAttested: result.VersionsAttested,
		LatestVersion:    result.LatestVersion,
	}, nil
}

// AttestPositive creates and submits a positive attestation for a tool.
// It returns nil result if rate-limited (silently skipped). Positive
// attestations include only the tool ID, outcome, and version — no params,
// no agent_runtime.
func (c *Client) AttestPositive(ctx context.Context, toolURI, version string, kp *signing.KeyPair) (*SubmitResult, error) {
	if !c.limiter.Allow(toolURI) {
		return nil, nil // silently skip
	}

	toolID, err := id.NewToolID(toolURI)
	if err != nil {
		return nil, fmt.Errorf("invalid tool URI: %w", err)
	}

	attesterDID := identity.DIDFromKey(kp.Public)
	now := time.Now().UTC().Truncate(time.Second)

	ta := &toolattest.ToolAttestation{
		ID:       id.NewToolAttestationID(),
		Attester: attesterDID,
		Tool:     toolID,
		Outcome:  toolattest.OutcomeSuccess,
		Claims:   map[string]string{},
		Version:  version,
		IssuedAt: now,
	}

	if err := attest.Seal(ta, kp); err != nil {
		return nil, fmt.Errorf("seal attestation: %w", err)
	}

	return c.submitAttestation(ctx, ta)
}

// PrepareNegative builds a negative attestation for pre-submission review.
// The caller MUST display the attestation to the user and obtain confirmation
// before calling [Client.SubmitPrepared]. This two-step flow enforces the
// mandatory pre-submission review for negative attestations.
func (c *Client) PrepareNegative(toolURI, version string, claims map[string]string, kp *signing.KeyPair) (*toolattest.ToolAttestation, error) {
	toolID, err := id.NewToolID(toolURI)
	if err != nil {
		return nil, fmt.Errorf("invalid tool URI: %w", err)
	}

	attesterDID := identity.DIDFromKey(kp.Public)
	now := time.Now().UTC().Truncate(time.Second)

	ta := &toolattest.ToolAttestation{
		ID:       id.NewToolAttestationID(),
		Attester: attesterDID,
		Tool:     toolID,
		Outcome:  toolattest.OutcomeNegative,
		Claims:   claims,
		Version:  version,
		IssuedAt: now,
	}

	// Validate but do not sign yet — signing happens at submission after
	// the user confirms.
	if err := ta.Validate(); err != nil {
		return nil, fmt.Errorf("validate attestation: %w", err)
	}

	return ta, nil
}

// SubmitPrepared signs and submits a previously prepared attestation.
// Use this after the user has reviewed and confirmed a negative attestation
// from [Client.PrepareNegative].
func (c *Client) SubmitPrepared(ctx context.Context, ta *toolattest.ToolAttestation, kp *signing.KeyPair) (*SubmitResult, error) {
	if err := attest.Seal(ta, kp); err != nil {
		return nil, fmt.Errorf("seal attestation: %w", err)
	}
	return c.submitAttestation(ctx, ta)
}

// Limiter returns the session limiter for direct inspection or allow checks.
// Callers that build and seal attestations locally (to support offline queuing)
// can call Limiter().Allow(toolURI) before building, matching the same rate
// limit that AttestPositive enforces internally.
func (c *Client) Limiter() *SessionLimiter { return c.limiter }

// SubmitSealed submits a pre-built, pre-signed attestation without rebuilding
// or re-sealing it. Use this when the caller has already called [attest.Seal]
// (e.g. to preserve the signed data for offline queuing) and only needs to
// transmit the result.
func (c *Client) SubmitSealed(ctx context.Context, ta *toolattest.ToolAttestation) (*SubmitResult, error) {
	return c.submitAttestation(ctx, ta)
}

// Retract signs a canonical deletion payload and sends it to the trust service.
// Only the original attester can retract their own attestation.
func (c *Client) Retract(ctx context.Context, attestationID string, attesterDID identity.DID, kp *signing.KeyPair) error {
	// encoding/json marshals map keys in sorted order, matching JCS for ASCII keys.
	payload, err := json.Marshal(map[string]string{
		"action":         "retract",
		"attestation_id": attestationID,
		"attester_did":   string(attesterDID),
	})
	if err != nil {
		return fmt.Errorf("marshal retraction payload: %w", err)
	}

	sig, err := signing.SignCanonical(kp, payload)
	if err != nil {
		return fmt.Errorf("sign retraction: %w", err)
	}

	return c.querier.RetractAttestation(ctx, attestationID, string(attesterDID), sig)
}

// submitAttestation converts a ToolAttestation to a submission and sends it.
func (c *Client) submitAttestation(ctx context.Context, ta *toolattest.ToolAttestation) (*SubmitResult, error) {
	sub := &AttestationSubmission{
		AttestationID: ta.ID.String(),
		AttesterDID:   string(ta.Attester),
		ToolURI:       ta.Tool.String(),
		Outcome:       string(ta.Outcome),
		Claims:        ta.Claims,
		Version:       ta.Version,
		Signature:     ta.Signature,
		IssuedAt:      ta.IssuedAt,
	}
	return c.querier.SubmitAttestation(ctx, sub)
}
