package relay

import (
	"sync"
	"time"
)

// RateLimiter implements a sliding-window rate limiter for STORE operations.
// It tracks per-sender timestamps and rejects requests when the count in
// the last hour exceeds the configured maximum.
//
// The default is 100 STORE operations per hour per registered identity.
type RateLimiter struct {
	maxPerHour int
	window     time.Duration
	mu         sync.Mutex
	timestamps map[string][]time.Time
	nowFunc    func() time.Time // overridable for testing
}

// NewRateLimiter creates a rate limiter that allows maxPerHour STORE operations
// per sender identity within a sliding one-hour window.
func NewRateLimiter(maxPerHour int) *RateLimiter {
	return &RateLimiter{
		maxPerHour: maxPerHour,
		window:     time.Hour,
		timestamps: make(map[string][]time.Time),
		nowFunc:    time.Now,
	}
}

// Allow checks if a sender is within the rate limit and records the attempt.
// Returns true if the operation is allowed, false if rate-limited.
func (rl *RateLimiter) Allow(senderAddr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFunc()
	cutoff := now.Add(-rl.window)

	// Prune old timestamps
	existing := rl.timestamps[senderAddr]
	pruned := existing[:0]
	for _, t := range existing {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}

	if len(pruned) >= rl.maxPerHour {
		rl.timestamps[senderAddr] = pruned
		return false
	}

	rl.timestamps[senderAddr] = append(pruned, now)
	return true
}
