// Package versioncheck compares the running CLI version against the latest
// published version and returns an update message when one is available.
package versioncheck

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const cacheTTL = 24 * time.Hour

// Check fetches the latest version from versionURL and compares it to
// currentVersion. Returns a message if an update is available, empty string
// otherwise. Never returns an error — failures are silently ignored so
// network issues do not block CLI usage.
func Check(ctx context.Context, currentVersion, versionURL, configDir string) string {
	if currentVersion == "dev" || currentVersion == "" {
		return ""
	}

	cacheFile := filepath.Join(configDir, "last-version-check")
	if msg, ok := readCache(cacheFile, currentVersion); ok {
		return msg
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	latest, err := fetchVersion(ctx, versionURL)
	if err != nil {
		return ""
	}

	var msg string
	if semverLess(currentVersion, latest) {
		msg = fmt.Sprintf(
			"Update available: v%s → v%s\nRun: curl -fsSL https://sigil-trust.dev/install.sh | sh",
			currentVersion, latest,
		)
	}

	writeCache(cacheFile, latest)
	return msg
}

func fetchVersion(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// readCache returns the cached message and true if the cache is still valid.
// The cache file format is: "<unix-timestamp>\n<latest-version>".
func readCache(path, currentVersion string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	parts := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(parts) != 2 {
		return "", false
	}

	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return "", false
	}

	if time.Since(time.Unix(ts, 0)) > cacheTTL {
		return "", false
	}

	latest := parts[1]
	if semverLess(currentVersion, latest) {
		return fmt.Sprintf(
			"Update available: v%s → v%s\nRun: curl -fsSL https://sigil-trust.dev/install.sh | sh",
			currentVersion, latest,
		), true
	}
	return "", true
}

func writeCache(path, latestVersion string) {
	data := fmt.Sprintf("%d\n%s", time.Now().Unix(), latestVersion)
	_ = os.WriteFile(path, []byte(data), 0o600)
}

// semverLess returns true if a < b using simple numeric comparison of
// major.minor.patch components. Both versions should be bare (no "v" prefix).
func semverLess(a, b string) bool {
	pa := parseSemver(a)
	pb := parseSemver(b)
	if pa == nil || pb == nil {
		return a != b && b > a // fallback to lexicographic
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parseSemver(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		nums[i] = n
	}
	return nums
}
