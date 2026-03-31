package scorecache_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fwilkerson/sigil-cli/internal/scorecache"
)

func newTestCache(t *testing.T) *scorecache.Cache {
	t.Helper()
	return scorecache.New(t.TempDir())
}

func makeScore(toolURI string) *scorecache.CachedScore {
	return &scorecache.CachedScore{
		ToolURI:          toolURI,
		Score:            0.85,
		Recommendation:   "use",
		Label:            "well-trusted",
		Provisional:      false,
		HasData:          true,
		Attestations:     10,
		Attesters:        3,
		SuccessRate:      0.9,
		VersionsAttested: 2,
		LatestVersion:    "1.0.0",
		CachedAt:         time.Now(),
	}
}

func TestPutThenGet(t *testing.T) {
	c := newTestCache(t)
	toolURI := "mcp://example.com/tool"
	want := makeScore(toolURI)

	if err := c.Put(toolURI, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := c.Get(toolURI)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil, want cached score")
	}

	if got.ToolURI != want.ToolURI {
		t.Errorf("ToolURI = %q, want %q", got.ToolURI, want.ToolURI)
	}
	if got.Score != want.Score {
		t.Errorf("Score = %v, want %v", got.Score, want.Score)
	}
	if got.Recommendation != want.Recommendation {
		t.Errorf("Recommendation = %q, want %q", got.Recommendation, want.Recommendation)
	}
	if got.Attestations != want.Attestations {
		t.Errorf("Attestations = %d, want %d", got.Attestations, want.Attestations)
	}
}

func TestGetExpiredReturnsNil(t *testing.T) {
	configDir := t.TempDir()
	c := scorecache.New(configDir)
	toolURI := "mcp://example.com/tool"

	// Write an entry with an old timestamp directly, bypassing Put.
	old := makeScore(toolURI)
	old.CachedAt = time.Now().Add(-2 * time.Hour) // two hours ago — expired

	dir := filepath.Join(configDir, "cache", "scores")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	h := sha256.Sum256([]byte(toolURI))
	fname := filepath.Join(dir, hex.EncodeToString(h[:])+".json")
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(fname, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := c.Get(toolURI)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("Get returned %+v, want nil for expired entry", got)
	}
}

func TestGetMissingToolReturnsNil(t *testing.T) {
	c := newTestCache(t)

	got, err := c.Get("mcp://example.com/missing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("Get returned %+v, want nil for missing entry", got)
	}
}

func TestGetBeforePutNoDirError(t *testing.T) {
	// configDir doesn't exist — Get should not fail, just return nil.
	configDir := filepath.Join(t.TempDir(), "nonexistent-subdir")
	c := scorecache.New(configDir)

	got, err := c.Get("mcp://example.com/tool")
	if err != nil {
		t.Fatalf("Get on missing dir returned error: %v", err)
	}
	if got != nil {
		t.Errorf("Get returned %+v, want nil", got)
	}
}

func TestHashProducesConsistentFilename(t *testing.T) {
	configDir := t.TempDir()
	c := scorecache.New(configDir)
	toolURI := "mcp://example.com/consistent"

	if err := c.Put(toolURI, makeScore(toolURI)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Compute the expected filename independently.
	h := sha256.Sum256([]byte(toolURI))
	expectedName := hex.EncodeToString(h[:]) + ".json"
	expectedPath := filepath.Join(configDir, "cache", "scores", expectedName)

	if _, err := os.Stat(expectedPath); err != nil {
		t.Errorf("expected file %q not found: %v", expectedPath, err)
	}

	// Get should return the same entry regardless of how many times we call it.
	for i := range 3 {
		got, err := c.Get(toolURI)
		if err != nil {
			t.Fatalf("Get call %d: %v", i, err)
		}
		if got == nil {
			t.Fatalf("Get call %d returned nil", i)
		}
	}
}
