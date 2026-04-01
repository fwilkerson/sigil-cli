// Package trust defines the shared protocol types for the Sigil trust service.
// These types are used by both transport adapters (gRPC) and client-side logic.
package trust

import (
	"context"
	"time"
)

// Querier abstracts the trust service backend. Implementations may use
// gRPC, the CLI, or an in-memory stub for testing.
type Querier interface {
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
