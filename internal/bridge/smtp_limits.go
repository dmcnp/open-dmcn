package bridge

import (
	"strings"
	"sync"

	"dmcn.dev/open-dmcn/internal/relay"
)

// Default inbound abuse-control limits. All are per the bridge's own SMTP
// listener and are independent of the relay's per-identity STORE limit (which
// only governs the bridge's own DMCN identity, not arbitrary legacy senders).
const (
	defaultInboundMaxPerIP     = 100 // messages per remote IP per hour
	defaultInboundMaxPerSender = 100 // messages per envelope sender per hour
	defaultInboundMaxConns     = 256 // concurrent SMTP connections
)

// inboundLimits enforces abuse controls on the inbound SMTP listener:
// per-IP and per-envelope-sender sliding-window message-rate limits, plus a
// global concurrent-connection cap. It is safe for concurrent use.
type inboundLimits struct {
	ipRate     *relay.RateLimiter
	senderRate *relay.RateLimiter

	maxConns int
	mu       sync.Mutex
	conns    int
}

// newInboundLimits builds the limit set, applying defaults for any non-positive
// value.
func newInboundLimits(maxPerIP, maxPerSender, maxConns int) *inboundLimits {
	if maxPerIP <= 0 {
		maxPerIP = defaultInboundMaxPerIP
	}
	if maxPerSender <= 0 {
		maxPerSender = defaultInboundMaxPerSender
	}
	if maxConns <= 0 {
		maxConns = defaultInboundMaxConns
	}
	return &inboundLimits{
		ipRate:     relay.NewRateLimiter(maxPerIP),
		senderRate: relay.NewRateLimiter(maxPerSender),
		maxConns:   maxConns,
	}
}

// acquireConn reserves a connection slot. It returns a release function and true
// if a slot was available, or (nil, false) if the concurrent-connection cap is
// reached. The release function is idempotent and must be called when the
// connection closes.
func (l *inboundLimits) acquireConn() (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns >= l.maxConns {
		return nil, false
	}
	l.conns++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.conns--
			l.mu.Unlock()
		})
	}, true
}

// allowMessage reports whether a message from the given remote IP and envelope
// sender is within the per-IP and per-sender rate limits, recording the attempt.
func (l *inboundLimits) allowMessage(ip, sender string) bool {
	if ip != "" && !l.ipRate.Allow(ip) {
		return false
	}
	if sender = strings.ToLower(strings.Trim(strings.TrimSpace(sender), "<>")); sender != "" && !l.senderRate.Allow(sender) {
		return false
	}
	return true
}

// ipKey normalizes a remote address (host or host:port) to a stable per-IP key.
func ipKey(addr string) string {
	if ip := parseHost(addr); ip != nil {
		return ip.String()
	}
	return addr
}
