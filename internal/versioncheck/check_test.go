package versioncheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCheck_UpdateAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.2.0"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	msg := Check(context.Background(), "0.1.0", srv.URL, dir)
	if msg == "" {
		t.Fatal("expected update message, got empty")
	}
	if want := "v0.1.0 → v0.2.0"; !contains(msg, want) {
		t.Errorf("message %q does not contain %q", msg, want)
	}
}

func TestCheck_AlreadyCurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.1.0"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	msg := Check(context.Background(), "0.1.0", srv.URL, dir)
	if msg != "" {
		t.Errorf("expected empty message, got %q", msg)
	}
}

func TestCheck_DevBuildSkipped(t *testing.T) {
	msg := Check(context.Background(), "dev", "http://should-not-be-called", t.TempDir())
	if msg != "" {
		t.Errorf("expected empty for dev build, got %q", msg)
	}
}

func TestCheck_EmptyVersionSkipped(t *testing.T) {
	msg := Check(context.Background(), "", "http://should-not-be-called", t.TempDir())
	if msg != "" {
		t.Errorf("expected empty for empty version, got %q", msg)
	}
}

func TestCheck_NetworkFailureSilent(t *testing.T) {
	dir := t.TempDir()
	msg := Check(context.Background(), "0.1.0", "http://127.0.0.1:1", dir)
	if msg != "" {
		t.Errorf("expected empty on network failure, got %q", msg)
	}
}

func TestCheck_CacheHit(t *testing.T) {
	dir := t.TempDir()
	cacheFile := filepath.Join(dir, "last-version-check")

	// Write a fresh cache saying latest is 0.3.0.
	data := strconv.FormatInt(time.Now().Unix(), 10) + "\n0.3.0"
	os.WriteFile(cacheFile, []byte(data), 0o644)

	// Should return update message without hitting network.
	msg := Check(context.Background(), "0.1.0", "http://should-not-be-called", dir)
	if msg == "" {
		t.Fatal("expected cached update message")
	}
	if want := "v0.1.0 → v0.3.0"; !contains(msg, want) {
		t.Errorf("message %q does not contain %q", msg, want)
	}
}

func TestCheck_CacheExpired(t *testing.T) {
	dir := t.TempDir()
	cacheFile := filepath.Join(dir, "last-version-check")

	// Write an expired cache.
	old := time.Now().Add(-25 * time.Hour).Unix()
	data := strconv.FormatInt(old, 10) + "\n0.3.0"
	os.WriteFile(cacheFile, []byte(data), 0o644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("0.4.0"))
	}))
	defer srv.Close()

	msg := Check(context.Background(), "0.1.0", srv.URL, dir)
	if want := "v0.1.0 → v0.4.0"; !contains(msg, want) {
		t.Errorf("expected fresh fetch result, got %q", msg)
	}
}

func TestSemverLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"0.1.0", "0.2.0", true},
		{"0.2.0", "0.1.0", false},
		{"0.1.0", "0.1.0", false},
		{"0.1.9", "0.2.0", true},
		{"1.0.0", "0.9.9", false},
		{"0.0.1", "0.0.2", true},
		{"1.2.3", "1.2.4", true},
		{"1.2.4", "1.2.4", false},
	}
	for _, tt := range tests {
		got := semverLess(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("semverLess(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
