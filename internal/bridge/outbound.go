package bridge

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/relay"
)

// outboundLimiter is the subset of relay.RateLimiter the outbound handler needs,
// extracted as an interface so tests can substitute a fake.
type outboundLimiter interface {
	Allow(senderAddr string) bool
}

// NOTE (open-dmcn reference implementation): the entitlement-aware daily BRIDGED-recipients cap
// (a fleet send-counter fed via the operator send-quota credential) is a product surface and is
// omitted. Outbound is bounded by the flat per-sender hourly limiter below; a self-host is its own
// send authority.

// outboundDedupMax bounds the set of recently-delivered message IDs kept for
// idempotency before it is reset (PoC-grade; a persistent store would replace
// this post-PoC alongside durable relay storage).
const outboundDedupMax = 4096

// messageDedup tracks message IDs already delivered, so a duplicate or replayed
// envelope is not delivered to the legacy recipient twice.
type messageDedup struct {
	mu   sync.Mutex
	seen map[[16]byte]struct{}
}

func newMessageDedup() *messageDedup {
	return &messageDedup{seen: make(map[[16]byte]struct{})}
}

func (d *messageDedup) seenBefore(id [16]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.seen[id]
	return ok
}

func (d *messageDedup) mark(id [16]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.seen) >= outboundDedupMax {
		d.seen = make(map[[16]byte]struct{})
	}
	d.seen[id] = struct{}{}
}

// OutboundHandler processes DMCN messages addressed to legacy email
// recipients and delivers them via SMTP.
type OutboundHandler struct {
	bridgeKP       *identity.IdentityKeyPair
	bridgeAddr     string
	deliverer      SMTPDeliverer
	lookup         LookupFunc
	profiles       *profileSet     // bridge↔dmcn domain mapping (one or more pairs)
	allowedSenders map[string]bool // sender DMCN domains this bridge relays for
	limiter        outboundLimiter
	dedup          *messageDedup
	audit          AuditLog
	log            logr.Logger
}

// OutboundConfig configures the outbound handler.
type OutboundConfig struct {
	BridgeKP   *identity.IdentityKeyPair
	BridgeAddr string
	Deliverer  SMTPDeliverer
	Lookup     LookupFunc
	// BridgeDomain/DMCNDomain are the default (single-profile) pair; Profiles adds more
	// {bridge↔dmcn} pairs. Outbound mail is From-rewritten + DKIM-signed to the bridge domain
	// of the sender's DMCN-domain profile.
	BridgeDomain string
	DMCNDomain   string
	Profiles     []DomainProfile
	// AllowedSenderDomains are extra DMCN domains whose users may relay outbound mail through
	// this bridge (the open-relay guard) on top of every profile's DMCN domain. This stops a
	// registered identity on some other domain using the bridge as an open relay.
	AllowedSenderDomains []string
	// OutboundRateLimit is the maximum outbound deliveries per sender per hour.
	// If <= 0, defaultOutboundRateLimit is used.
	OutboundRateLimit int
	Audit             AuditLog // nil ⇒ no-op
	Log               logr.Logger
}

// defaultOutboundRateLimit caps outbound deliveries per sender per hour.
const defaultOutboundRateLimit = 100

// NewOutboundHandler creates a new outbound message handler.
func NewOutboundHandler(cfg OutboundConfig) *OutboundHandler {
	profiles := newProfileSet(cfg.Profiles, cfg.BridgeDomain, cfg.DMCNDomain)
	// A sender is authorized if its DMCN domain is one the bridge serves (a profile), widened
	// by any explicit AllowedSenderDomains.
	allowed := make(map[string]bool)
	for _, d := range profiles.dmcnDomains() {
		allowed[strings.ToLower(d)] = true
	}
	for _, d := range cfg.AllowedSenderDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			allowed[d] = true
		}
	}

	limit := cfg.OutboundRateLimit
	if limit <= 0 {
		limit = defaultOutboundRateLimit
	}

	audit := cfg.Audit
	if audit == nil {
		audit = nopAuditLog{}
	}

	return &OutboundHandler{
		bridgeKP:       cfg.BridgeKP,
		bridgeAddr:     cfg.BridgeAddr,
		deliverer:      cfg.Deliverer,
		lookup:         cfg.Lookup,
		profiles:       profiles,
		allowedSenders: allowed,
		limiter:        relay.NewRateLimiter(limit),
		dedup:          newMessageDedup(),
		audit:          audit,
		log:            cfg.Log,
	}
}

// HandleEnvelope decrypts a DMCN envelope addressed to the bridge,
// verifies the sender, delivers the message via SMTP, and returns a
// signed delivery receipt.
func (h *OutboundHandler) HandleEnvelope(ctx context.Context, env *message.EncryptedEnvelope) (*BridgeDeliveryReceipt, error) {
	// 1. Decrypt
	sm, err := message.Decrypt(env, h.bridgeKP.X25519Private, h.bridgeKP.X25519Public)
	if err != nil {
		return nil, fmt.Errorf("bridge: decrypt: %w", err)
	}

	// 2. Verify sender signature
	if err := sm.Verify(); err != nil {
		return nil, fmt.Errorf("bridge: verify sender: %w", err)
	}

	// 3. Log warning — PRD requirement: bridge must log when decrypting
	// message content for outbound delivery.
	h.log.Warnf("TRUST DISCLOSURE: decrypting message from %s for outbound SMTP delivery to %s",
		sm.Plaintext.SenderAddress, sm.Plaintext.RecipientAddress)

	// 4. Verify sender exists in registry (the lookup is the existence check; the record itself
	// is no longer needed after dropping the fleet send-rate counter).
	senderAddr := sm.Plaintext.SenderAddress
	if _, err := h.lookup(ctx, senderAddr); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrSenderNotFound, senderAddr, err)
	}

	// 5. Authorize the sender for relaying. Open registration means any identity
	// can sign a valid message, so existence is not enough — the sender must be
	// on a domain this bridge relays for, or it could use us as an open relay to
	// any legacy address.
	if !h.senderAuthorized(senderAddr) {
		h.log.Warnf("rejecting outbound from unauthorized sender %s (domain not served by this bridge)", senderAddr)
		h.audit.Record(AuditEvent{Action: "outbound.reject", From: senderAddr, To: sm.Plaintext.RecipientAddress, Detail: "sender not authorized"})
		return nil, fmt.Errorf("%w: %s", ErrSenderNotAuthorized, senderAddr)
	}

	// Resolve the sender's domain profile: outbound From-rewrite + DKIM align to this bridge
	// domain, and legacy-recipient detection uses this pair.
	bridgeDomain, dmcnDomain := h.profiles.forDMCNDomain(domainOf(senderAddr))

	// 6. Check recipient is a legacy address
	recipientAddr := sm.Plaintext.RecipientAddress
	if !IsLegacyAddress(recipientAddr, bridgeDomain, dmcnDomain) {
		return nil, fmt.Errorf("%w: %s", ErrNotLegacyAddress, recipientAddr)
	}

	// 6b. Reject header-injection attempts before any deliverer builds an RFC5322
	// message. A malicious DMCN sender could embed CR/LF/NUL in the subject or an
	// address to smuggle extra SMTP headers (e.g. a hidden Bcc). The body may
	// legitimately contain newlines and is not checked here.
	smtpFrom := DMCNToSMTPFrom(senderAddr, bridgeDomain)
	for _, f := range []struct{ name, val string }{
		{"sender", smtpFrom}, {"recipient", recipientAddr}, {"subject", sm.Plaintext.Subject},
	} {
		if hasHeaderInjection(f.val) {
			h.log.Warnf("rejecting outbound from %s: header injection in %s", senderAddr, f.name)
			h.audit.Record(AuditEvent{Action: "outbound.reject", From: senderAddr, To: recipientAddr, Detail: "header injection in " + f.name})
			return nil, fmt.Errorf("%w: in %s", ErrUnsafeHeader, f.name)
		}
	}

	// 7. Idempotency: never deliver the same DMCN message twice. A duplicate or
	// replayed envelope returns a success receipt without re-delivering (and
	// without consuming rate-limit quota).
	msgID := sm.Plaintext.MessageID
	if h.dedup.seenBefore(msgID) {
		h.log.Infof("skipping duplicate outbound delivery of %x to %s", msgID, recipientAddr)
		return h.makeReceipt(msgID, recipientAddr, nil)
	}

	// 8. Enforce the per-sender outbound rate limit just before delivery, so
	// rejected/unauthorized/duplicate messages do not consume quota. This flat hourly limiter is a
	// coarse backstop; the entitlement-aware daily bridged cap below is the real IP-reputation gate.
	if !h.limiter.Allow(senderAddr) {
		h.log.Warnf("rejecting outbound from %s: rate limit exceeded", senderAddr)
		return nil, fmt.Errorf("%w: %s", ErrOutboundRateLimited, senderAddr)
	}

	// 9. Deliver via SMTP (smtpFrom validated in step 6b). The full message is passed so the
	// deliverer renders a faithful MIME body — content type, attachments, and threading headers.
	deliverErr := h.deliverer.Deliver(ctx, smtpFrom, recipientAddr, &sm.Plaintext)
	if deliverErr != nil {
		h.log.Warnf("outbound delivery failed to %s: %v", recipientAddr, deliverErr)
		h.audit.Record(AuditEvent{Action: "outbound.deliver", From: senderAddr, To: recipientAddr, Success: false, Detail: deliverErr.Error()})
	} else {
		h.dedup.mark(msgID) // mark delivered only on success, so failures can retry
		h.log.Infof("outbound message delivered from %s to %s via SMTP", senderAddr, recipientAddr)
		h.audit.Record(AuditEvent{Action: "outbound.deliver", From: senderAddr, To: recipientAddr, Success: true})
	}

	// 10. Construct and sign the delivery receipt.
	receipt, err := h.makeReceipt(msgID, recipientAddr, deliverErr)
	if err != nil {
		return nil, err
	}
	return receipt, deliverErr
}

// makeReceipt builds and signs a delivery receipt. deliverErr == nil means
// success; otherwise its message is recorded in ErrorDetail.
func (h *OutboundHandler) makeReceipt(msgID [16]byte, recipient string, deliverErr error) (*BridgeDeliveryReceipt, error) {
	receipt := &BridgeDeliveryReceipt{
		OriginalMessageID: msgID,
		RecipientEmail:    recipient,
		BridgeAddress:     h.bridgeAddr,
		DeliveredAt:       time.Now().UTC(),
		Success:           deliverErr == nil,
	}
	if deliverErr != nil {
		receipt.ErrorDetail = deliverErr.Error()
	}
	if err := receipt.Sign(h.bridgeKP.Ed25519Private); err != nil {
		return nil, fmt.Errorf("bridge: sign receipt: %w", err)
	}
	return receipt, nil
}

// senderAuthorized reports whether a DMCN sender address is on a domain this
// bridge is configured to relay outbound mail for.
func (h *OutboundHandler) senderAuthorized(senderAddr string) bool {
	return h.allowedSenders[domainOf(senderAddr)]
}

// hasHeaderInjection reports whether s contains a character that could break out
// of a single RFC5322 header field — CR, LF, or NUL.
func hasHeaderInjection(s string) bool {
	return strings.ContainsAny(s, "\r\n\x00")
}
