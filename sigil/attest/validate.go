package attest

import "fmt"

// ValidateClaims checks that a claims map is within the size limits defined by
// the protocol. Both Sigil and ToolAttestation call this from their Validate().
func ValidateClaims(claims map[string]string) error {
	if len(claims) > MaxClaimKeys {
		return fmt.Errorf("too many claim keys: %d (max %d)", len(claims), MaxClaimKeys)
	}
	total := 0
	for k, v := range claims {
		if len(k) > MaxClaimKeyLen {
			return fmt.Errorf("claim key %q exceeds max length of %d", k, MaxClaimKeyLen)
		}
		if len(v) > MaxClaimValueLen {
			return fmt.Errorf("claim value for key %q exceeds max length of %d", k, MaxClaimValueLen)
		}
		total += len(k) + len(v)
	}
	if total > MaxClaimsTotalLen {
		return fmt.Errorf("total claims size %d exceeds max of %d bytes", total, MaxClaimsTotalLen)
	}
	return nil
}
