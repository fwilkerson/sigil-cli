package attest

// Well-known claim key constants shared across all attestation types.
// These are conventions, not constraints — the Claims map remains open.
const (
	// ClaimIntent describes what the party tried to do.
	ClaimIntent = "intent"

	// ClaimResult describes what actually happened.
	ClaimResult = "result"

	// ClaimErrorCode is a machine-readable error identifier.
	ClaimErrorCode = "error_code"
)

// Claims size limits enforced by Validate() on all Sealable types.
// These prevent denial-of-service via oversized payloads.
const (
	MaxClaimKeys      = 32
	MaxClaimKeyLen    = 64
	MaxClaimValueLen  = 1024
	MaxClaimsTotalLen = 8192 // 8 KB
)
