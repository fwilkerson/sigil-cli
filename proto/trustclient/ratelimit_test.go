package trustclient

import (
	"testing"
	"time"
)

func TestSessionLimiter_OncePerSession(t *testing.T) {
	l := NewSessionLimiter(0) // zero cooldown = once per session

	if !l.Allow("mcp://example.com/tool") {
		t.Fatal("first call should be allowed")
	}
	if l.Allow("mcp://example.com/tool") {
		t.Fatal("second call to same tool should be blocked")
	}
	if !l.Allow("mcp://example.com/other") {
		t.Fatal("different tool should be allowed")
	}
}

func TestSessionLimiter_WithCooldown(t *testing.T) {
	l := NewSessionLimiter(time.Hour)

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	toolURI := "mcp://example.com/tool"

	if !l.allowAt(toolURI, now) {
		t.Fatal("first call should be allowed")
	}
	if l.allowAt(toolURI, now.Add(30*time.Minute)) {
		t.Fatal("call within cooldown should be blocked")
	}
	if !l.allowAt(toolURI, now.Add(61*time.Minute)) {
		t.Fatal("call after cooldown should be allowed")
	}
}

func TestSessionLimiter_Reset(t *testing.T) {
	l := NewSessionLimiter(0)
	toolURI := "mcp://example.com/tool"

	l.Allow(toolURI)
	if l.Allow(toolURI) {
		t.Fatal("should be blocked before reset")
	}

	l.Reset()

	if !l.Allow(toolURI) {
		t.Fatal("should be allowed after reset")
	}
}
