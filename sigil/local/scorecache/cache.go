// Package scorecache provides a local file-based cache for trust score check
// results. Cache entries are stored as JSON files in {configDir}/cache/scores/,
// keyed by the SHA256 hex of the tool URI. Entries expire after [TTL].
package scorecache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// TTL is the maximum age of a valid cache entry.
const TTL = time.Hour

// Cache is a file-based score cache rooted at a configDir subdirectory.
type Cache struct {
	dir string
}

// New returns a Cache that stores entries under {configDir}/cache/scores/.
func New(configDir string) *Cache {
	return &Cache{dir: filepath.Join(configDir, "cache", "scores")}
}

// CachedScore holds the fields of a trust check result alongside the time the
// entry was written. The Recommendation field is stored as a plain string so
// that the struct round-trips cleanly through JSON without importing the
// trust client package.
type CachedScore struct {
	ToolURI          string    `json:"tool_uri"`
	Score            float64   `json:"score"`
	Recommendation   string    `json:"recommendation"`
	Label            string    `json:"label"`
	Provisional      bool      `json:"provisional"`
	HasData          bool      `json:"has_data"`
	Attestations     int       `json:"attestations"`
	Attesters        int       `json:"attesters"`
	SuccessRate      float64   `json:"success_rate"`
	VersionsAttested int       `json:"versions_attested"`
	LatestVersion    string    `json:"latest_version"`
	CachedAt         time.Time `json:"cached_at"`
}

// Get returns the cached score for toolURI if it exists and has not expired.
// It returns (nil, nil) when the entry is missing, unreadable, or expired.
// The cache directory is created lazily; a missing directory is not an error.
func (c *Cache) Get(toolURI string) (*CachedScore, error) {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(c.path(toolURI))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cs CachedScore
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, nil // treat corrupt entry as a miss
	}

	if time.Since(cs.CachedAt) > TTL {
		return nil, nil // expired
	}

	return &cs, nil
}

// Put writes cs to the cache as a JSON file keyed by toolURI. The cache
// directory is created if it does not exist.
func (c *Cache) Put(toolURI string, cs *CachedScore) error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(cs)
	if err != nil {
		return err
	}

	return os.WriteFile(c.path(toolURI), data, 0o600)
}

// path returns the file path for the given tool URI.
func (c *Cache) path(toolURI string) string {
	h := sha256.Sum256([]byte(toolURI))
	return filepath.Join(c.dir, hex.EncodeToString(h[:])+".json")
}
