package id_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/sigil/id"
)

// TestNewToolID_ValidURIs verifies that well-formed URIs for all supported
// schemes are accepted and produce the correct canonical form.
func TestNewToolID_ValidURIs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		wantStr string
	}{
		{
			name:    "mcp basic",
			input:   "mcp://github.com/user/repo",
			wantStr: "mcp://github.com/user/repo",
		},
		{
			name:    "openclaw basic",
			input:   "openclaw://skill-name/tool",
			wantStr: "openclaw://skill-name/tool",
		},
		{
			name:    "github basic",
			input:   "github://user/repo",
			wantStr: "github://user/repo",
		},
		{
			name:    "https basic",
			input:   "https://marketplace.example.com/tool",
			wantStr: "https://marketplace.example.com/tool",
		},
		{
			name:    "https preserves path case",
			input:   "https://example.com/MyTool/v1",
			wantStr: "https://example.com/MyTool/v1",
		},
		{
			name:    "mcp with deep path",
			input:   "mcp://github.com/org/repo/path/to/tool",
			wantStr: "mcp://github.com/org/repo/path/to/tool",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := id.NewToolID(tc.input)
			if err != nil {
				t.Fatalf("NewToolID(%q) returned unexpected error: %v", tc.input, err)
			}
			if got.String() != tc.wantStr {
				t.Fatalf("got %q, want %q", got.String(), tc.wantStr)
			}
		})
	}
}

// TestNewToolID_Canonicalization verifies that different representations of
// the same tool produce equal ToolIDs after canonicalization.
func TestNewToolID_Canonicalization(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a    string
		b    string
	}{
		{
			name: "uppercase scheme and host normalized",
			a:    "MCP://GitHub.com/User/Repo/",
			b:    "mcp://github.com/user/repo",
		},
		{
			name: "trailing slash stripped",
			a:    "github://user/repo/",
			b:    "github://user/repo",
		},
		{
			name: "query parameters stripped",
			a:    "https://example.com/tool?v=2",
			b:    "https://example.com/tool",
		},
		{
			name: "fragment stripped",
			a:    "https://example.com/tool#section",
			b:    "https://example.com/tool",
		},
		{
			name: "mcp case-insensitive path",
			a:    "mcp://github.com/User/Repo",
			b:    "mcp://github.com/user/repo",
		},
		{
			name: "openclaw case-insensitive path",
			a:    "openclaw://Skill-Name/Tool",
			b:    "openclaw://skill-name/tool",
		},
		{
			name: "github case-insensitive path",
			a:    "github://MyUser/MyRepo",
			b:    "github://myuser/myrepo",
		},
		{
			name: "multiple trailing slashes stripped",
			a:    "mcp://github.com/user/repo///",
			b:    "mcp://github.com/user/repo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := id.NewToolID(tc.a)
			if err != nil {
				t.Fatalf("NewToolID(%q): %v", tc.a, err)
			}
			b, err := id.NewToolID(tc.b)
			if err != nil {
				t.Fatalf("NewToolID(%q): %v", tc.b, err)
			}
			if a != b {
				t.Fatalf("expected equal ToolIDs: %q != %q", a.String(), b.String())
			}
		})
	}
}

// TestNewToolID_HttpsPreservesPathCase verifies that https:// does not
// lowercase path components (per RFC 3986, paths are case-sensitive).
func TestNewToolID_HttpsPreservesPathCase(t *testing.T) {
	t.Parallel()

	got, err := id.NewToolID("https://example.com/MyTool/SubPath")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.String() != "https://example.com/MyTool/SubPath" {
		t.Fatalf("https:// path should preserve case, got %q", got.String())
	}
}

// TestNewToolID_InvalidURIs verifies that malformed or policy-violating URIs
// are rejected with an error.
func TestNewToolID_InvalidURIs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "unsupported scheme ftp",
			input: "ftp://example.com/tool",
		},
		{
			name:  "unsupported scheme custom",
			input: "custom://example.com/tool",
		},
		{
			name:  "no scheme",
			input: "github.com/user/repo",
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "empty path",
			input: "mcp://github.com",
		},
		{
			name:  "empty path with trailing slash only",
			input: "mcp://github.com/",
		},
		{
			name:  "userinfo in mcp URI",
			input: "mcp://user:pass@github.com/repo",
		},
		{
			name:  "userinfo in https URI",
			input: "https://user:pass@example.com/tool",
		},
		{
			name:  "userinfo username only",
			input: "github://user@github.com/repo",
		},
		{
			name:  "URI exceeds 2048 characters",
			input: "mcp://example.com/" + strings.Repeat("a", 2048),
		},
		{
			name:  "control character in URI",
			input: "mcp://github.com/user\x00/repo",
		},
		{
			name:  "control character tab",
			input: "mcp://github.com/user\x09/repo",
		},
		{
			name:  "control character newline",
			input: "mcp://github.com/user\x0a/repo",
		},
		{
			name:  "DEL character",
			input: "mcp://github.com/user\x7f/repo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := id.NewToolID(tc.input)
			if err == nil {
				t.Fatalf("NewToolID(%q) should have returned an error", tc.input)
			}
		})
	}
}

// TestToolID_ZeroValue verifies the behaviour of an uninitialized ToolID.
func TestToolID_ZeroValue(t *testing.T) {
	t.Parallel()

	var zero id.ToolID
	if !zero.IsZero() {
		t.Fatal("zero value ToolID should return IsZero() == true")
	}
	if zero.String() != "" {
		t.Fatalf("zero value ToolID.String() should be empty, got %q", zero.String())
	}
}

// TestToolID_IsZero_NonZero verifies that a constructed ToolID is not zero.
func TestToolID_IsZero_NonZero(t *testing.T) {
	t.Parallel()

	got, err := id.NewToolID("mcp://github.com/user/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IsZero() {
		t.Fatal("non-zero ToolID should return IsZero() == false")
	}
}

// TestToolID_MarshalText verifies that MarshalText returns the canonical URI.
func TestToolID_MarshalText(t *testing.T) {
	t.Parallel()

	input := "mcp://github.com/user/repo"
	tid, err := id.NewToolID(input)
	if err != nil {
		t.Fatalf("NewToolID: %v", err)
	}
	b, err := tid.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(b) != input {
		t.Fatalf("MarshalText() = %q, want %q", string(b), input)
	}
}

// TestToolID_UnmarshalText verifies that UnmarshalText accepts a valid URI and
// canonicalizes it the same way as NewToolID.
func TestToolID_UnmarshalText(t *testing.T) {
	t.Parallel()

	t.Run("valid URI", func(t *testing.T) {
		t.Parallel()
		var got id.ToolID
		if err := got.UnmarshalText([]byte("github://user/repo")); err != nil {
			t.Fatalf("UnmarshalText: %v", err)
		}
		if got.String() != "github://user/repo" {
			t.Fatalf("got %q, want %q", got.String(), "github://user/repo")
		}
	})

	t.Run("invalid URI returns error", func(t *testing.T) {
		t.Parallel()
		var got id.ToolID
		if err := got.UnmarshalText([]byte("ftp://example.com/tool")); err == nil {
			t.Fatal("expected error for invalid URI")
		}
	})

	t.Run("canonicalization applied", func(t *testing.T) {
		t.Parallel()
		var got id.ToolID
		if err := got.UnmarshalText([]byte("MCP://GitHub.com/User/Repo/")); err != nil {
			t.Fatalf("UnmarshalText: %v", err)
		}
		if got.String() != "mcp://github.com/user/repo" {
			t.Fatalf("got %q, want %q", got.String(), "mcp://github.com/user/repo")
		}
	})
}

// TestToolID_RoundTrip verifies that a ToolID survives a MarshalText /
// UnmarshalText round-trip with its canonical value intact.
func TestToolID_RoundTrip(t *testing.T) {
	t.Parallel()

	uris := []string{
		"mcp://github.com/user/repo",
		"openclaw://skill-name/tool",
		"github://user/repo",
		"https://marketplace.example.com/tool",
	}
	for _, uri := range uris {
		t.Run(uri, func(t *testing.T) {
			t.Parallel()
			orig, err := id.NewToolID(uri)
			if err != nil {
				t.Fatalf("NewToolID: %v", err)
			}
			b, err := orig.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText: %v", err)
			}
			var got id.ToolID
			if err := got.UnmarshalText(b); err != nil {
				t.Fatalf("UnmarshalText: %v", err)
			}
			if got != orig {
				t.Fatalf("round-trip: got %q, want %q", got.String(), orig.String())
			}
		})
	}
}

// TestToolID_JSON_RoundTrip verifies that a ToolID survives a JSON
// marshal/unmarshal cycle.
func TestToolID_JSON_RoundTrip(t *testing.T) {
	t.Parallel()

	type wrapper struct {
		Tool id.ToolID `json:"tool"`
	}
	orig := wrapper{}
	var err error
	orig.Tool, err = id.NewToolID("mcp://github.com/user/repo")
	if err != nil {
		t.Fatalf("NewToolID: %v", err)
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got wrapper
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Tool != orig.Tool {
		t.Fatalf("got %q, want %q", got.Tool.String(), orig.Tool.String())
	}
}

// TestToolAttestationID_New verifies that NewToolAttestationID generates a
// non-zero, unique ID each call.
func TestToolAttestationID_New(t *testing.T) {
	t.Parallel()

	a := id.NewToolAttestationID()
	b := id.NewToolAttestationID()
	if a.IsZero() {
		t.Fatal("new ToolAttestationID should not be zero")
	}
	if a == b {
		t.Fatal("two new ToolAttestationIDs should be different")
	}
}

// TestToolAttestationID_Parse verifies parse/round-trip behaviour.
func TestToolAttestationID_Parse(t *testing.T) {
	t.Parallel()

	orig := id.NewToolAttestationID()
	parsed, err := id.ParseToolAttestationID(orig.String())
	if err != nil {
		t.Fatalf("ParseToolAttestationID: %v", err)
	}
	if parsed != orig {
		t.Fatalf("got %s, want %s", parsed, orig)
	}
}

// TestToolAttestationID_ParseInvalid verifies that bad input returns an error.
func TestToolAttestationID_ParseInvalid(t *testing.T) {
	t.Parallel()

	_, err := id.ParseToolAttestationID("not-a-ulid")
	if err == nil {
		t.Fatal("expected error for invalid ULID string")
	}
}

// TestToolAttestationID_IsZero verifies zero value detection.
func TestToolAttestationID_IsZero(t *testing.T) {
	t.Parallel()

	var zero id.ToolAttestationID
	if !zero.IsZero() {
		t.Fatal("zero value should return IsZero() == true")
	}
	if id.NewToolAttestationID().IsZero() {
		t.Fatal("new ID should not be zero")
	}
}

// TestToolAttestationID_Time verifies that the embedded timestamp is within a
// reasonable window of now.
func TestToolAttestationID_Time(t *testing.T) {
	t.Parallel()

	before := time.Now().Add(-time.Second)
	aid := id.NewToolAttestationID()
	after := time.Now().Add(time.Second)

	ts := aid.Time()
	if ts.Before(before) || ts.After(after) {
		t.Fatalf("timestamp %v not in [%v, %v]", ts, before, after)
	}
}

// TestToolAttestationID_MarshalText verifies the text encoding round-trip.
func TestToolAttestationID_MarshalText(t *testing.T) {
	t.Parallel()

	orig := id.NewToolAttestationID()
	b, err := orig.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var got id.ToolAttestationID
	if err := got.UnmarshalText(b); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if got != orig {
		t.Fatalf("round-trip: got %s, want %s", got, orig)
	}
}

// TestToolAttestationID_JSON_RoundTrip verifies JSON marshal/unmarshal.
func TestToolAttestationID_JSON_RoundTrip(t *testing.T) {
	t.Parallel()

	type wrapper struct {
		ID id.ToolAttestationID `json:"id"`
	}
	orig := wrapper{ID: id.NewToolAttestationID()}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got wrapper
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != orig.ID {
		t.Fatalf("got %s, want %s", got.ID, orig.ID)
	}
}
