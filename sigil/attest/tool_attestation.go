package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/id"
	"github.com/fwilkerson/sigil-cli/sigil/identity"
)

// Outcome is the binary result of a tool interaction.
type Outcome string

// Defined outcome values.
const (
	OutcomeSuccess  Outcome = "success"
	OutcomeNegative Outcome = "negative"
)

// Tool-specific well-known claim key constants.
const (
	// ClaimFunction is the function or endpoint invoked on the tool.
	ClaimFunction = "function"

	// ClaimParams records parameter shapes (type names, key names, counts),
	// NOT raw values. Raw values may contain PII and should only be included
	// when the user explicitly approves during pre-submission review for
	// negative attestations. Positive auto-attestations should not include
	// params at all.
	ClaimParams = "params"
)

// ToolAttestation is a signed attestation from a user about a tool.
// It implements [Sealable]. Unlike party-to-party sigils, the tool does not
// participate in signing; the attestation is unilateral.
type ToolAttestation struct {
	ID        id.ToolAttestationID `json:"id"`
	Attester  identity.DID         `json:"attester"`
	Tool      id.ToolID            `json:"tool"`
	Outcome   Outcome              `json:"outcome"`
	Claims    map[string]string    `json:"claims"`
	Version   string               `json:"version"`
	IssuedAt  time.Time            `json:"issued_at"`
	Signature []byte               `json:"signature"`
}

// toolAttestPayload is the versioned canonical representation for signing.
type toolAttestPayload struct {
	V        int               `json:"v"`
	ID       string            `json:"id"`
	Attester string            `json:"attester"`
	Tool     string            `json:"tool"`
	Outcome  string            `json:"outcome"`
	Claims   map[string]string `json:"claims"`
	Version  string            `json:"version"`
	IssuedAt string            `json:"issued_at"`
}

// SigningPayload returns the deterministic canonical byte representation of the
// tool attestation, used for signing and verification.
func (ta *ToolAttestation) SigningPayload() ([]byte, error) {
	claims := ta.Claims
	if claims == nil {
		claims = map[string]string{}
	}
	p := toolAttestPayload{
		V:        1,
		ID:       ta.ID.String(),
		Attester: ta.Attester.String(),
		Tool:     ta.Tool.String(),
		Outcome:  string(ta.Outcome),
		Claims:   claims,
		Version:  ta.Version,
		IssuedAt: ta.IssuedAt.UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal tool attestation payload: %w", err)
	}
	return data, nil
}

// SetSignature stores the computed signature on the attestation.
func (ta *ToolAttestation) SetSignature(sig []byte) { ta.Signature = sig }

// GetSignature returns the attestation's signature.
func (ta *ToolAttestation) GetSignature() []byte { return ta.Signature }

// Signer returns the attester's DID — the entity that signs this attestation.
func (ta *ToolAttestation) Signer() identity.DID { return ta.Attester }

// Validate checks that all required fields are present and valid.
func (ta *ToolAttestation) Validate() error {
	if ta.ID.IsZero() {
		return errors.New("missing attestation ID")
	}
	if ta.Attester.IsZero() {
		return errors.New("missing attester")
	}
	if !strings.HasPrefix(string(ta.Attester), "did:") {
		return errors.New("attester is not a valid DID")
	}
	if ta.Tool.IsZero() {
		return errors.New("missing tool")
	}
	if ta.Outcome != OutcomeSuccess && ta.Outcome != OutcomeNegative {
		return fmt.Errorf("invalid outcome %q: must be %q or %q", ta.Outcome, OutcomeSuccess, OutcomeNegative)
	}
	if ta.IssuedAt.IsZero() {
		return errors.New("missing issued_at")
	}
	if err := ValidateClaims(ta.Claims); err != nil {
		return err
	}
	return nil
}

// Compile-time check that *ToolAttestation implements Sealable.
var _ Sealable = (*ToolAttestation)(nil)
