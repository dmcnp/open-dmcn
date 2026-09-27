package bridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
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
	return keyFor(id, recipient)
}

func keyFor(id [16]byte, recipient string) deliveryKey {
	return deliveryKey{id: id, recipient: strings.ToLower(strings.TrimSpace(recipient))}
}

// limitSet is a set of the sending limits a message has passed.
type limitSet uint8

// limitHourly is the flat per-sender hourly limit, the one sending limit this bridge applies.
const limitHourly limitSet = 1

// retrying remembers what the bridge needs to keep about a message while it is being retried:
// which sending limits have already let it through and counted it, so a retry is charged only to
// a limit that has not, and the key its sender was verified with, so a key rotation while it
// waits does not turn a message they really sent into a forgery. An entry lives while the message
// is retried and goes when the bridge is finished with it.
type retrying struct {
	mu   sync.Mutex
	recs map[deliveryKey]retryRecord
}

type retryRecord struct {
	passed limitSet          // the sending limits already passed
	signer ed25519.PublicKey // the signing key verified against the sender's record; nil until it was
}

func (r *retrying) get(id [16]byte, recipient string) retryRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recs[keyFor(id, recipient)]
}

func (r *retrying) update(id [16]byte, recipient string, change func(*retryRecord)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recs == nil || len(r.recs) >= outboundDedupMax {
		r.recs = make(map[deliveryKey]retryRecord) // a backstop: entries go when messages finish
	}
	k := keyFor(id, recipient)
	rec := r.recs[k]
	change(&rec)
	r.recs[k] = rec
}

func (r *retrying) forget(id [16]byte, recipient string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.recs, keyFor(id, recipient))
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
	retrying       retrying // what is remembered about each message being retried
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
	a := h.Attempt(ctx, env)
	return a.Receipt, a.Err
}

// OutboundAttempt is what one attempt to send a queued envelope came to. The bridge decides from
// it whether it is finished with the envelope, and what, if anything, to tell the sender, without
// opening the envelope again.
type OutboundAttempt struct {
	// Plaintext is the opened message; nil when the envelope could not be opened.
	Plaintext *message.PlaintextMessage
	// Sender is the sender's registry record, set once the message's signing key has been checked
	// against it — the only point from which the named sender is known to have written it, and
	// so the only one from which they may be told anything.
	Sender *identity.IdentityRecord
	// Receipt is the verdict when there is one: delivered, or refused for good by the remote side.
	Receipt *BridgeDeliveryReceipt
	// Err says why the message was not delivered; nil when it was.
	Err error
	// Retry reports that no verdict was reached and a later attempt may reach one: a sender
	// lookup that failed, a key that may belong to a record not yet refreshed, a rate limit, or a
	// remote server that deferred.
	Retry bool
}

// Attempt is HandleEnvelope reporting everything the bridge needs to act on the outcome.
func (h *OutboundHandler) Attempt(ctx context.Context, env *message.EncryptedEnvelope) *OutboundAttempt {
	o, err := h.Open(env)
	if err != nil {
		return &OutboundAttempt{Err: err}
	}
	return h.Send(ctx, o)
}

// OpenedMessage is an outbound envelope the bridge has decrypted and whose signature verifies:
// enough to know where it is going, before anything that needs the network.
type OpenedMessage struct {
	Plaintext *message.PlaintextMessage
	audience  Audience
}

// Open decrypts an envelope addressed to the bridge and verifies its signature. An envelope that
// fails either will always fail, so its error, ErrUndecryptable, is final.
func (h *OutboundHandler) Open(env *message.EncryptedEnvelope) (*OpenedMessage, error) {
	// Decrypt AND verify the sender signature. Both formats are accepted and each is verified
	// the way it was signed — see decryptForBridge. Split envelopes are the normal shape for
	// anything a browser composes; handling only the older single-blob form meant every real
	// outbound message failed AEAD authentication here, which stayed invisible for as long as
	// nothing could discover the bridge to send to it.
	pt, audience, err := decryptForBridge(env, h.bridgeKP)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUndecryptable, err)
	}
	return &OpenedMessage{Plaintext: pt, audience: audience}, nil
}

// Send is Attempt for a message already opened.
func (h *OutboundHandler) Send(ctx context.Context, o *OpenedMessage) *OutboundAttempt {
	a := &OutboundAttempt{Plaintext: o.Plaintext}
	pt, audience := o.Plaintext, o.audience
	fail := func(retry bool, err error) *OutboundAttempt {
		a.Err, a.Retry = err, retry
		switch {
		case !retry:
			h.retrying.forget(pt.MessageID, pt.RecipientAddress)
		case a.Sender != nil:
			h.retrying.update(pt.MessageID, pt.RecipientAddress, func(r *retryRecord) { r.signer = pt.SenderPublicKey })
		}
		return a
	}

	// 3. Log warning — the bridge must log when decrypting
	// message content for outbound delivery.
	h.log.Warnf("TRUST DISCLOSURE: decrypting message from %s for outbound SMTP delivery to %s",
		pt.SenderAddress, pt.RecipientAddress)

	// 4. Resolve the sender and bind the claimed address to the signing key. The signature
	// checked in decryptForBridge verifies against the public key carried INSIDE the message,
	// so on its own it proves self-consistency and nothing about ownership. The relay's STORE
	// gate does bind a key to an address, but to the request's CLEARTEXT sender; SenderAddress
	// here comes out of the DECRYPTED header, and the two are independent fields. Without this
	// comparison a legitimate holder of any address on a served domain can have us deliver as
	// any other address on it — rewritten to the bridge domain and DKIM-signed, so it arrives
	// fully DMARC-aligned.
	//
	// A mismatch is retried rather than refused for good: the record we hold may be one a key
	// rotation has since replaced. A forgery never passes, and its named sender is never told.
	senderAddr := pt.SenderAddress
	senderRec, err := h.lookup(ctx, senderAddr)
	if err != nil {
		return fail(true, fmt.Errorf("%w: %s: %v", ErrSenderNotFound, senderAddr, err))
	}
	if !h.signedBySender(senderRec, pt) {
		h.log.Warnf("rejecting outbound from %s: signing key is not the key registered for that address", senderAddr)
		h.audit.Record(AuditEvent{Action: "outbound.reject", From: senderAddr, To: pt.RecipientAddress, Detail: "sender key does not match registry record"})
		return fail(true, fmt.Errorf("%w: %s", ErrSenderKeyMismatch, senderAddr))
	}
	a.Sender = senderRec

	// 5. Authorize the sender for relaying. Open registration means any identity
	// can sign a valid message, so existence is not enough — the sender must be
	// on a domain this bridge relays for, or it could use us as an open relay to
	// any legacy address.
	if !h.senderAuthorized(senderAddr) {
		h.log.Warnf("rejecting outbound from unauthorized sender %s (domain not served by this bridge)", senderAddr)
		h.audit.Record(AuditEvent{Action: "outbound.reject", From: senderAddr, To: pt.RecipientAddress, Detail: "sender not authorized"})
		return fail(false, fmt.Errorf("%w: %s", ErrSenderNotAuthorized, senderAddr))
	}

	// Resolve the sender's domain profile: outbound From-rewrite + DKIM align to this bridge
	// domain, and legacy-recipient detection uses this pair.
	bridgeDomain, dmcnDomain := h.profiles.forDMCNDomain(domainOf(senderAddr))

	// 6. Check recipient is a legacy address
	recipientAddr := pt.RecipientAddress
	if !IsLegacyAddress(recipientAddr, bridgeDomain, dmcnDomain) {
		return fail(false, fmt.Errorf("%w: %s", ErrNotLegacyAddress, recipientAddr))
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
			return fail(false, fmt.Errorf("%w: in %s", ErrUnsafeHeader, f.name))
		}
	}

	// 7. Idempotency: never deliver the same DMCN message to the same recipient twice. A
	// duplicate or replayed envelope returns a success receipt without re-delivering (and without
	// consuming rate-limit quota). Scoped per RECIPIENT — one compose to several people is one
	// message ID with several copies, and treating those as duplicates drops all but the first.
	msgID := pt.MessageID
	if h.dedup.seenBefore(msgID, recipientAddr) {
		h.log.Infof("skipping duplicate outbound delivery of %x to %s", msgID, recipientAddr)
		receipt, err := h.makeReceipt(msgID, recipientAddr, nil)
		if err != nil {
			return fail(true, err)
		}
		a.Receipt = receipt
		return a
	}

	// 8. Enforce the per-sender outbound rate limit just before delivery, so
	// rejected/unauthorized/duplicate messages do not consume quota. Checked and counted once per
	// message and recipient: a retry after the remote server deferred is the same message, already
	// counted and already let through.
	if h.retrying.get(msgID, recipientAddr).passed&limitHourly == 0 {
		if !h.limiter.Allow(senderAddr) {
			h.log.Warnf("rejecting outbound from %s: rate limit exceeded", senderAddr)
			return fail(true, fmt.Errorf("%w: %s", ErrOutboundRateLimited, senderAddr))
		}
		h.retrying.update(msgID, recipientAddr, func(r *retryRecord) { r.passed |= limitHourly })
	}

	// 9. Deliver via SMTP (smtpFrom validated in step 6b). The full message is passed so the
	// deliverer renders a faithful MIME body — content type, attachments, and threading headers.
	deliverErr := h.deliverer.Deliver(ctx, smtpFrom, recipientAddr, pt, audience)
	if deliverErr != nil {
		h.log.Warnf("outbound delivery failed to %s: %v", recipientAddr, deliverErr)
		h.audit.Record(AuditEvent{Action: "outbound.deliver", From: senderAddr, To: recipientAddr, Success: false, Detail: deliverErr.Error()})
		// A deferral (4xx, an unreachable server, a DNS timeout) is not a verdict: the remote
		// side asked us to come back, which is what mail servers retry for days.
		if errors.Is(deliverErr, ErrDeliveryDeferred) {
			return fail(true, deliverErr)
		}
		h.retrying.forget(msgID, recipientAddr)
	} else {
		h.retrying.forget(msgID, recipientAddr)
		h.dedup.mark(msgID, recipientAddr) // only on success, so failures can retry
		h.log.Infof("outbound message delivered from %s to %s via SMTP", senderAddr, recipientAddr)
		h.audit.Record(AuditEvent{Action: "outbound.deliver", From: senderAddr, To: recipientAddr, Success: true})
	}

	// 10. Construct and sign the delivery receipt.
	receipt, err := h.makeReceipt(msgID, recipientAddr, deliverErr)
	if err != nil {
		return fail(true, err)
	}
	a.Receipt, a.Err = receipt, deliverErr
	return a
}

// makeReceipt builds and signs a delivery receipt. deliverErr == nil means
// success; otherwise its message is recorded in ErrorDetail.
func (h *OutboundHandler) makeReceipt(msgID [16]byte, recipient string, deliverErr error) (*BridgeDeliveryReceipt, error) {
	detail := ""
	if deliverErr != nil {
		detail = deliverErr.Error()
	}
	return h.signReceipt(msgID, recipient, deliverErr == nil, detail)
}

// signReceipt builds and signs a delivery receipt with the given outcome.
func (h *OutboundHandler) signReceipt(msgID [16]byte, recipient string, success bool, detail string) (*BridgeDeliveryReceipt, error) {
	receipt := &BridgeDeliveryReceipt{
		OriginalMessageID: msgID,
		RecipientEmail:    recipient,
		BridgeAddress:     h.bridgeAddr,
		BridgeCredential:  h.credential,
		DeliveredAt:       time.Now().UTC(),
		Success:           success,
		ErrorDetail:       detail,
	}
	if err := receipt.Sign(h.bridgeKP.Ed25519Private); err != nil {
		return nil, fmt.Errorf("bridge: sign receipt: %w", err)
	}
	return receipt, nil
}

// signedBySender reports whether pt was signed with its sender's key: the key senderRec
// publishes now, or the key an earlier attempt at this same message verified against their
// record then — a sender who rotates keys while their message waits still sent it.
func (h *OutboundHandler) signedBySender(senderRec *identity.IdentityRecord, pt *message.PlaintextMessage) bool {
	if bytes.Equal(senderRec.Ed25519Public, pt.SenderPublicKey) {
		return true
	}
	signer := h.retrying.get(pt.MessageID, pt.RecipientAddress).signer
	return signer != nil && bytes.Equal(signer, pt.SenderPublicKey)
}

// errNotSent is a message whose lifetime ran out before any worker got to it.
var errNotSent = errors.New("bridge: not sent within its lifetime")

// Expire is the attempt for a message whose lifetime ran out before it could be sent at all:
// its sender is looked up and checked as Send would, so Abandon tells them only if they really
// sent it.
func (h *OutboundHandler) Expire(ctx context.Context, o *OpenedMessage) *OutboundAttempt {
	a := &OutboundAttempt{Plaintext: o.Plaintext, Err: errNotSent, Retry: true}
	if rec, err := h.lookup(ctx, o.Plaintext.SenderAddress); err == nil && h.signedBySender(rec, o.Plaintext) {
		a.Sender = rec
	}
	return a
}

// refusalNotice is what the sender is told about a refusal no retry can change, in words that
// do not need the protocol explained; empty when there is nothing they could act on.
func refusalNotice(err error) string {
	switch {
	case errors.Is(err, ErrSenderNotAuthorized):
		return "Your address is not one this service sends ordinary email for."
	case errors.Is(err, ErrNotLegacyAddress):
		return "That address belongs to this service, so the message has to be sent to it directly, not as ordinary email."
	case errors.Is(err, ErrUnsafeHeader):
		return "The subject or an address contains characters that email does not allow."
	}
	return ""
}

// Abandon ends the attempts at a message the bridge is finished with but has no verdict for —
// refused for good, or still failing after `after` — records that in the audit trail, and
// returns the failure notice its sender should get, or nil when nobody should be told. Only a
// sender whose signing key was checked against their record is told anything: an envelope the
// bridge cannot open names no one, and a notice to a sender it never verified would land on
// whoever a forger chose to name.
func (h *OutboundHandler) Abandon(a *OutboundAttempt, after time.Duration) *BridgeDeliveryReceipt {
	action, notice := "outbound.drop", refusalNotice(a.Err)
	if a.Retry {
		action = "outbound.expire"
		notice = fmt.Sprintf("It still could not be sent after %s, so we have stopped trying.", readableDuration(after))
	}
	var from, to string
	if a.Plaintext != nil {
		from, to = a.Plaintext.SenderAddress, a.Plaintext.RecipientAddress
		h.retrying.forget(a.Plaintext.MessageID, to)
	}
	h.audit.Record(AuditEvent{Action: action, From: from, To: to, Detail: a.Err.Error()})
	if a.Sender == nil || notice == "" {
		return nil
	}
	receipt, err := h.signReceipt(a.Plaintext.MessageID, to, false, notice)
	if err != nil {
		h.log.Warnf("outbound: failure receipt for %x: %v", a.Plaintext.MessageID, err)
		return nil
	}
	return receipt
}

// readableDuration writes a lifetime the way the notice's reader would say it: "5 days", not
// "120h0m0s".
func readableDuration(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d == day:
		return "1 day"
	case d%day == 0:
		return fmt.Sprintf("%d days", d/day)
	case d == time.Hour:
		return "1 hour"
	case d%time.Hour == 0:
		return fmt.Sprintf("%d hours", d/time.Hour)
	}
	return d.String()
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
