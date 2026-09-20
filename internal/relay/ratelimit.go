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

// Rotation limits, per address, per day. An account re-keys on the order of once a year; a bad
// day might need two or three in a row, and past that a loop is the only explanation.
//
// What a loop costs, and why this is required rather than tidy: every rotation appends to the
// address's history record, which is append-only and grows without bound, and pushes the oldest
// transition off the capped chain the identity record carries — so an unbounded loop inflates
// storage on every node and walks a reader's pinned key out of the window that would have
// explained it.
//
// A LIMITER rather than a protocol-level minimum interval between rotations, deliberately. A
// floor in the rules would refuse the one case that most needs a second rotation immediately: the
// key just rotated TO turning out to be compromised as well. A limiter delays; it never makes a
// legitimate re-key impossible, and the budget refills as the window slides.
const rotationsPerDay = 4

// NewRotationLimiter bounds how often one address may be re-keyed on this node.
func NewRotationLimiter() *RateLimiter {
	return &RateLimiter{
		maxPerHour: rotationsPerDay,
		window:     24 * time.Hour,
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
