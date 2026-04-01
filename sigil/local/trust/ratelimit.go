package trust

import (
	"sync"
	"time"
)

// SessionLimiter prevents duplicate attestations for the same tool within a
// session or time window. This avoids flooding the trust service when an agent
// invokes the same tool repeatedly.
type SessionLimiter struct {
	mu       sync.Mutex
	seen     map[string]time.Time
	cooldown time.Duration
}

// NewSessionLimiter creates a limiter that allows one attestation per tool
// per cooldown period. A zero cooldown means once-per-session (no expiry).
func NewSessionLimiter(cooldown time.Duration) *SessionLimiter {
	return &SessionLimiter{
		seen:     make(map[string]time.Time),
		cooldown: cooldown,
	}
}

// Allow returns true if the tool has not been attested within the cooldown
// window, and records the current time. Returns false if rate-limited.
func (l *SessionLimiter) Allow(toolURI string) bool {
	return l.allowAt(toolURI, time.Now())
}

// allowAt is the testable core of Allow.
func (l *SessionLimiter) allowAt(toolURI string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if last, ok := l.seen[toolURI]; ok {
		if l.cooldown == 0 || now.Sub(last) < l.cooldown {
			return false
		}
	}
	l.seen[toolURI] = now
	return true
}

// Reset clears all rate limit state.
func (l *SessionLimiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = make(map[string]time.Time)
}
