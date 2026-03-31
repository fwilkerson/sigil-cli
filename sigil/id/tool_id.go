package id

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/oklog/ulid/v2"
)

// allowedSchemes defines the URI schemes accepted by NewToolID. The map value
// controls whether path components are lowercased during canonicalization:
//
//   - true  — lowercase the path (scheme is case-insensitive by convention,
//     e.g. github:// where usernames and repo names are case-insensitive).
//   - false — preserve path case per RFC 3986 (e.g. https:// where path
//     components may be case-sensitive).
//
// To add a new scheme, insert it here. No other code needs to change.
var allowedSchemes = map[string]bool{
	"mcp":      true,
	"openclaw": true,
	"github":   true,
	"https":    false,
}

const maxToolIDLen = 2048

// ToolID is a URI-based identifier for a tool, skill, or MCP server. It is
// NOT a DID — it identifies a tool by where it lives (registry, repository,
// or marketplace URL) rather than by a cryptographic key.
//
// # Version agnosticity
//
// ToolIDs should be version-agnostic. Version information belongs in the
// ToolAttestation.Version field, not embedded in the URI. Avoid creating
// separate ToolIDs for different versions of the same tool (e.g.
// "openclaw://skill/v1" and "openclaw://skill/v2"). Instead, use a single
// ToolID and record the version in the attestation.
//
// # Multiple ecosystems
//
// The same physical tool may appear in multiple registries and therefore have
// multiple ToolIDs (e.g. both a github:// and an mcp:// identifier). Alias
// resolution across ecosystems is a future concern and is not handled here.
//
// # Monorepo granularity
//
// "github://user/repo" identifies the repository, not a specific tool within
// it. Finer-grained identification (e.g. "github://user/repo/path/to/tool")
// is valid but callers must be consistent when creating attestations.
//
// # Future cryptographic identity
//
// Tools may optionally acquire a DID in the future for two-party attestation,
// where the tool itself co-signs. The ToolID and the tool's DID will coexist:
// the ToolID identifies the tool; the DID enables it to sign.
type ToolID struct{ v string }

// NewToolID parses, validates, and canonicalizes a URI into a ToolID.
//
// Canonicalization rules applied in order:
//  1. Reject control characters (U+0000–U+001F, U+007F) and other
//     non-printable characters anywhere in the URI.
//  2. Reject URIs longer than 2048 characters.
//  3. Parse as a URL and validate structure.
//  4. Lowercase the scheme and host.
//  5. Reject unknown schemes (only mcp, openclaw, https, github are accepted).
//  6. Reject userinfo (credentials in URIs are a security risk).
//  7. Reject an empty path.
//  8. Strip trailing slashes from the path.
//  9. Strip query parameters and fragments.
//  10. For schemes where paths are case-insensitive (mcp, openclaw, github),
//     lowercase the path. For https, preserve path case per RFC 3986.
func NewToolID(uri string) (ToolID, error) {
	if err := rejectControlChars(uri); err != nil {
		return ToolID{}, fmt.Errorf("tool ID: %w", err)
	}
	if len(uri) > maxToolIDLen {
		return ToolID{}, fmt.Errorf("tool ID: URI exceeds maximum length of %d characters", maxToolIDLen)
	}

	u, err := url.Parse(uri)
	if err != nil {
		return ToolID{}, fmt.Errorf("tool ID: invalid URI: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return ToolID{}, fmt.Errorf("tool ID: missing scheme")
	}

	lowercase, ok := allowedSchemes[scheme]
	if !ok {
		schemes := make([]string, 0, len(allowedSchemes))
		for s := range allowedSchemes {
			schemes = append(schemes, s+"://")
		}
		return ToolID{}, fmt.Errorf("tool ID: unsupported scheme %q (accepted: %s)", scheme, strings.Join(schemes, ", "))
	}

	if u.User != nil {
		return ToolID{}, fmt.Errorf("tool ID: userinfo is not allowed in tool URIs")
	}

	host := strings.ToLower(u.Host)
	if host == "" {
		return ToolID{}, fmt.Errorf("tool ID: missing host")
	}

	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		return ToolID{}, fmt.Errorf("tool ID: empty path")
	}
	if lowercase {
		path = strings.ToLower(path)
	}

	canonical := scheme + "://" + host + path
	return ToolID{v: canonical}, nil
}

// rejectControlChars returns an error if s contains any control character
// (U+0000–U+001F, U+007F) or non-printable Unicode code point.
func rejectControlChars(s string) error {
	for i, r := range s {
		if r == unicode.ReplacementChar {
			return fmt.Errorf("invalid character at byte %d", i)
		}
		if !unicode.IsPrint(r) {
			return fmt.Errorf("non-printable character %U at byte %d", r, i)
		}
	}
	return nil
}

// String returns the canonical URI string representation of the ToolID.
// The zero value returns an empty string.
func (t ToolID) String() string { return t.v }

// IsZero returns true if the ToolID is the zero value (no URI was set).
func (t ToolID) IsZero() bool { return t.v == "" }

// MarshalText implements encoding.TextMarshaler. It marshals the canonical URI
// as a UTF-8 string, suitable for use in JSON and other text formats.
func (t ToolID) MarshalText() ([]byte, error) {
	return []byte(t.v), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. It validates and
// canonicalizes the URI, identical to calling NewToolID.
func (t *ToolID) UnmarshalText(data []byte) error {
	v, err := NewToolID(string(data))
	if err != nil {
		return err
	}
	t.v = v.v
	return nil
}

// ToolAttestationID identifies a tool attestation record. It follows the same
// typed-ULID pattern as SigilID, AuditID, and other ID types in this package,
// giving tool attestations their own identifier space separate from
// party-to-party sigils.
type ToolAttestationID struct{ v ulid.ULID }

// NewToolAttestationID generates a new unique ToolAttestationID.
func NewToolAttestationID() ToolAttestationID { return ToolAttestationID{v: mustNew()} }

// ParseToolAttestationID parses a ULID string into a ToolAttestationID.
func ParseToolAttestationID(s string) (ToolAttestationID, error) {
	v, err := ulid.ParseStrict(s)
	if err != nil {
		return ToolAttestationID{}, fmt.Errorf("parse ToolAttestationID: %w", err)
	}
	return ToolAttestationID{v: v}, nil
}

// String returns the ULID string representation.
func (id ToolAttestationID) String() string { return id.v.String() }

// Time returns the timestamp embedded in the ULID.
func (id ToolAttestationID) Time() time.Time { return ulid.Time(id.v.Time()) }

// IsZero returns true if the ID is the zero value.
func (id ToolAttestationID) IsZero() bool { return id.v == ulid.ULID{} }

// MarshalText implements encoding.TextMarshaler for JSON support.
func (id ToolAttestationID) MarshalText() ([]byte, error) { return id.v.MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler for JSON support.
func (id *ToolAttestationID) UnmarshalText(data []byte) error { return id.v.UnmarshalText(data) }
