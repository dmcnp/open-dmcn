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

// outboundDedupMax bounds the set of recently-delivered deliveries kept for idempotency before it
// is reset (PoC-grade; a persistent store would replace this alongside durable relay storage).
const outboundDedupMax = 4096

// deliveryKey identifies one delivery: a message TO a particular recipient.
//
// Keying on the message ID alone was wrong, and wrong in a way that silently lost mail. A client
// composing to several people seals one copy per recipient, and every copy carries the SAME
// message ID — that is what makes them one conversation. So a message addressed to two legacy
// recipients looked like a redelivery of itself, and everyone after the first was dropped as a
// duplicate, with a SUCCESS receipt to the sender.
//
// Recipient is the legacy address, lowercased: what is being deduplicated is "did this message
// already reach this person", and SMTP addresses are not case-sensitive in the domain.
type deliveryKey struct {
	id        [16]byte
	recipient string
}

// messageDedup tracks deliveries already made, so a duplicate or replayed envelope is not
// delivered to the same legacy recipient twice.
type messageDedup struct {
	mu   sync.Mutex
	seen map[deliveryKey]struct{}
}

func newMessageDedup() *messageDedup {
	return &messageDedup{seen: make(map[deliveryKey]struct{})}
}

func (d *messageDedup) key(id [16]byte, recipient string) deliveryKey {
	return deliveryKey{id: id, recipient: strings.ToLower(strings.TrimSpace(recipient))}
}

func (d *messageDedup) seenBefore(id [16]byte, recipient string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.seen[d.key(id, recipient)]
	return ok
}

func (d *messageDedup) mark(id [16]byte, recipient string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.seen) >= outboundDedupMax {
		d.seen = make(map[deliveryKey]struct{})
	}
	d.seen[d.key(id, recipient)] = struct{}{}
}

// OutboundHandler processes DMCN messages addressed to legacy email
// recipients and delivers them via SMTP.
type OutboundHandler struct {
	bridgeKP       *identity.IdentityKeyPair
	bridgeAddr     string
	credential     *identity.Credential
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
	// Credential is the bridge's root-signed `bridge` credential, stamped into every delivery
	// receipt so the DMCN sender can verify it without a directory lookup.
	Credential *identity.Credential
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
		credential:     cfg.Credential,
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
	// 1. Decrypt AND verify the sender signature. Both formats are accepted and each is verified
	// the way it was signed — see decryptForBridge. Split envelopes are the normal shape for
	// anything a browser composes; handling only the older single-blob form meant every real
	// outbound message failed AEAD authentication here, which stayed invisible for as long as
	// nothing could discover the bridge to send to it.
	pt, audience, err := decryptForBridge(env, h.bridgeKP)
	if err != nil {
		return nil, fmt.Errorf("bridge: decrypt: %w", err)
	}

	// 3. Log warning — the bridge must log when decrypting
	// message content for outbound delivery.
	h.log.Warnf("TRUST DISCLOSURE: decrypting message from %s for outbound SMTP delivery to %s",
		pt.SenderAddress, pt.RecipientAddress)

	// 4. Verify sender exists in registry (the lookup is the existence check; the record itself
	// is no longer needed after dropping the fleet send-rate counter).
	senderAddr := pt.SenderAddress
	if _, err := h.lookup(ctx, senderAddr); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrSenderNotFound, senderAddr, err)
	}

	// 5. Authorize the sender for relaying. Open registration means any identity
	// can sign a valid message, so existence is not enough — the sender must be
	// on a domain this bridge relays for, or it could use us as an open relay to
	// any legacy address.
	if !h.senderAuthorized(senderAddr) {
		h.log.Warnf("rejecting outbound from unauthorized sender %s (domain not served by this bridge)", senderAddr)
		h.audit.Record(AuditEvent{Action: "outbound.reject", From: senderAddr, To: pt.RecipientAddress, Detail: "sender not authorized"})
		return nil, fmt.Errorf("%w: %s", ErrSenderNotAuthorized, senderAddr)
	}

	// Resolve the sender's domain profile: outbound From-rewrite + DKIM align to this bridge
	// domain, and legacy-recipient detection uses this pair.
	bridgeDomain, dmcnDomain := h.profiles.forDMCNDomain(domainOf(senderAddr))

	// 6. Check recipient is a legacy address
	recipientAddr := pt.RecipientAddress
	if !IsLegacyAddress(recipientAddr, bridgeDomain, dmcnDomain) {
		return nil, fmt.Errorf("%w: %s", ErrNotLegacyAddress, recipientAddr)
	}

	// 6b. Reject header-injection attempts before any deliverer builds an RFC5322
	// message. A malicious DMCN sender could embed CR/LF/NUL in the subject or an
	// address to smuggle extra SMTP headers (e.g. a hidden Bcc). The body may
	// legitimately contain newlines and is not checked here.
	smtpFrom := DMCNToSMTPFrom(senderAddr, bridgeDomain)
	for _, f := range []struct{ name, val string }{
		{"sender", smtpFrom}, {"recipient", recipientAddr}, {"subject", pt.Subject},
	} {
		if hasHeaderInjection(f.val) {
			h.log.Warnf("rejecting outbound from %s: header injection in %s", senderAddr, f.name)
			h.audit.Record(AuditEvent{Action: "outbound.reject", From: senderAddr, To: recipientAddr, Detail: "header injection in " + f.name})
			return nil, fmt.Errorf("%w: in %s", ErrUnsafeHeader, f.name)
		}
	}

	// 7. Idempotency: never deliver the same DMCN message to the same recipient twice. A
	// duplicate or replayed envelope returns a success receipt without re-delivering (and without
	// consuming rate-limit quota). Scoped per RECIPIENT — one compose to several people is one
	// message ID with several copies, and treating those as duplicates drops all but the first.
	msgID := pt.MessageID
	if h.dedup.seenBefore(msgID, recipientAddr) {
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
	deliverErr := h.deliverer.Deliver(ctx, smtpFrom, recipientAddr, pt, audience)
	if deliverErr != nil {
		h.log.Warnf("outbound delivery failed to %s: %v", recipientAddr, deliverErr)
		h.audit.Record(AuditEvent{Action: "outbound.deliver", From: senderAddr, To: recipientAddr, Success: false, Detail: deliverErr.Error()})
	} else {
		h.dedup.mark(msgID, recipientAddr) // only on success, so failures can retry
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
		BridgeCredential:  h.credential,
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

// decryptForBridge opens an envelope addressed to the bridge in whichever format it arrived in,
// verifies the sender signature, and returns the plaintext.
//
// Verification is inside this function on purpose. The two formats sign different things — the
// older one signs the whole plaintext, a split one signs the HEADER — so a caller that decrypted
// first and verified afterwards would have to know which shape it got, and would eventually check
// the wrong signature against the wrong bytes. Reassembling the split parts into a PlaintextMessage
// does not weaken anything: the header signature covers BodyHash and BodyContentAddress, and
// DecryptBody refuses a body that does not match them.
func decryptForBridge(env *message.EncryptedEnvelope, kp *identity.IdentityKeyPair) (*message.PlaintextMessage, Audience, error) {
	if !env.IsSplit() {
		// The legacy whole-message form has no audience list at all, so a message in that shape
		// can only ever be addressed to its single recipient.
		sm, err := message.Decrypt(env, kp.X25519Private, kp.X25519Public)
		if err != nil {
			return nil, Audience{}, err
		}
		if err := sm.Verify(); err != nil {
			return nil, Audience{}, fmt.Errorf("verify sender: %w", err)
		}
		return &sm.Plaintext, Audience{}, nil
	}

	sh, err := message.DecryptHeader(env, kp.X25519Private, kp.X25519Public)
	if err != nil {
		return nil, Audience{}, fmt.Errorf("header: %w", err)
	}
	if err := sh.Verify(); err != nil {
		return nil, Audience{}, fmt.Errorf("verify sender: %w", err)
	}
	content, err := message.DecryptBody(env, &sh.Header, kp.X25519Private, kp.X25519Public)
	if err != nil {
		return nil, Audience{}, fmt.Errorf("body: %w", err)
	}
	h := sh.Header
	// Bcc is intentionally not carried: it is signed into the header the SENDER kept, but a
	// recipient copy never contains it, and it must never reach an outbound header.
	audience := Audience{To: h.To, Cc: h.Cc}
	return &message.PlaintextMessage{
		Version:          h.Version,
		MessageID:        h.MessageID,
		ThreadID:         h.ThreadID,
		SenderAddress:    h.SenderAddress,
		SenderPublicKey:  h.SenderPublicKey,
		RecipientAddress: h.RecipientAddress,
		SentAt:           h.SentAt,
		Subject:          h.Subject,
		Body:             content.Body,
		Attachments:      content.Attachments,
		// The text/html rendering lives here, and dropping it silently down-converts every
		// formatted message to plain text on the way out. buildMIME already emits
		// multipart/alternative when it is present — it would simply never be given one.
		Alternatives: content.Alternatives,
		ReplyToID:    h.ReplyToID,
	}, audience, nil
}

// DecryptForBridgeForTest exposes decryptForBridge to the external test package, so a test can
// assert that the delivery path and the receipt path read the same envelope identically. They
// diverged once, and the symptom was invisible until a real message was delivered.
func DecryptForBridgeForTest(env *message.EncryptedEnvelope, kp *identity.IdentityKeyPair) (*message.PlaintextMessage, Audience, error) {
	return decryptForBridge(env, kp)
}
