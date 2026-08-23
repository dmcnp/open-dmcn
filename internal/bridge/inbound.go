package bridge

import (
	"context"
	"fmt"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// DeliverFunc routes a finished (split, v2) envelope to a recipient — STOREd to
// the recipient's relay hints like any client sender, or into the bridge's own
// mailbox/store when the bridge IS the recipient's relay (avoiding a self-dial).
type DeliverFunc func(ctx context.Context, recipient *identity.IdentityRecord, env *message.EncryptedEnvelope) error

// LookupFunc looks up an identity record by address from the registry.
type LookupFunc func(ctx context.Context, address string) (*identity.IdentityRecord, error)

// InboundHandler processes inbound SMTP messages and delivers them as
// encrypted DMCN envelopes to the recipient's relay node.
type InboundHandler struct {
	bridgeKP     *identity.IdentityKeyPair
	bridgeAddr   string
	credential   *identity.Credential
	authVerifier AuthVerifier
	lookup       LookupFunc
	deliver      DeliverFunc
	profiles     *profileSet // bridge↔dmcn domain mapping (one or more pairs)
	audit        AuditLog
	log          logr.Logger
}

// InboundConfig configures the inbound handler.
type InboundConfig struct {
	BridgeKP   *identity.IdentityKeyPair
	BridgeAddr string
	// Credential is the bridge's root-signed `bridge` credential, stamped into every
	// classification record so recipients can verify the verdict without a directory lookup.
	Credential   *identity.Credential
	AuthVerifier AuthVerifier
	Lookup       LookupFunc
	Deliver      DeliverFunc
	// BridgeDomain/DMCNDomain are the default (single-profile) domain pair; Profiles adds more
	// {bridge↔dmcn} pairs a single bridge serves (hosted multi-tenant). Inbound mail is mapped
	// by the recipient's bridge domain.
	BridgeDomain string
	DMCNDomain   string
	Profiles     []DomainProfile
	Audit        AuditLog // nil ⇒ no-op
	Log          logr.Logger
}

// NewInboundHandler creates a new inbound message handler.
func NewInboundHandler(cfg InboundConfig) *InboundHandler {
	audit := cfg.Audit
	if audit == nil {
		audit = nopAuditLog{}
	}
	return &InboundHandler{
		bridgeKP:     cfg.BridgeKP,
		bridgeAddr:   cfg.BridgeAddr,
		credential:   cfg.Credential,
		authVerifier: cfg.AuthVerifier,
		lookup:       cfg.Lookup,
		deliver:      cfg.Deliver,
		profiles:     newProfileSet(cfg.Profiles, cfg.BridgeDomain, cfg.DMCNDomain),
		audit:        audit,
		log:          cfg.Log,
	}
}

// servesBridgeDomain reports whether the recipient domain is one this bridge serves (RCPT
// confinement at the SMTP layer).
func (h *InboundHandler) servesBridgeDomain(domain string) bool {
	return h.profiles.servesBridgeDomain(domain)
}

// HandleMessage processes an inbound SMTP message, classifies it, wraps it
// in a DMCN envelope, and stores it on the relay.
func (h *InboundHandler) HandleMessage(ctx context.Context, senderIP, from, to string, rawMsg []byte) error {
	// 1. Verify authentication
	authResult, err := h.authVerifier.Verify(ctx, senderIP, from, rawMsg)
	if err != nil {
		return fmt.Errorf("bridge: auth verify: %w", err)
	}

	// 2. Classify, and drop hard authentication failures outright (DMARC
	// failure under a p=reject policy) rather than delivering them.
	if ShouldReject(authResult) {
		h.log.Warnf("rejecting inbound message from %s (%s): DMARC failure under reject policy", from, senderIP)
		h.audit.Record(AuditEvent{Action: "inbound.reject", From: from, To: to, SenderIP: senderIP, Detail: "DMARC failure under reject policy"})
		return fmt.Errorf("%w: from %s", ErrMessageRejected, from)
	}
	tier := Classify(authResult)
	h.log.Debugf("classified %s from %s as tier %d", to, from, tier)

	// 2b. Loop prevention. Parse the header block once (reused for bounce
	// suppression below). Drop messages that have traversed too many MTAs — the
	// classic forwarding-loop signal.
	hdr, hdrErr := parseHeaders(rawMsg)
	if hdrErr == nil {
		if hops := receivedHopCount(hdr); hops > maxReceivedHops {
			h.log.Warnf("dropping inbound from %s: mail loop (%d Received hops > %d)", from, hops, maxReceivedHops)
			h.audit.Record(AuditEvent{Action: "inbound.reject", From: from, To: to, SenderIP: senderIP, Detail: "mail loop"})
			return fmt.Errorf("%w: %d Received hops", ErrMailLoop, hops)
		}
	}

	// 3. Construct and sign classification record
	classRec := NewClassificationRecord(h.bridgeAddr, h.bridgeKP.Ed25519Public, from, authResult, tier)
	// The credential is what makes the verdict believable; without it the record is just a
	// signature by an unknown key.
	classRec.BridgeCredential = h.credential
	if err := classRec.Sign(h.bridgeKP.Ed25519Private); err != nil {
		return fmt.Errorf("bridge: sign classification: %w", err)
	}

	classBytes, err := classRec.Marshal()
	if err != nil {
		return fmt.Errorf("bridge: marshal classification: %w", err)
	}

	// 4. Map bridge address to DMCN address using the recipient domain's profile.
	bridgeDomain, dmcnDomain := h.profiles.forBridgeDomain(domainOf(to))
	dmcnAddr := SMTPToDMCN(to, bridgeDomain, dmcnDomain)

	// 5. Look up recipient
	recipientRec, err := h.lookup(ctx, dmcnAddr)
	if err != nil {
		// Bounce suppression: never reject (and thereby trigger a bounce) a
		// null-sender or auto-submitted message — that is how bounce loops form
		// (RFC 5321 §6.1, RFC 3834). Accept and drop it instead.
		if isNullSender(from) || (hdrErr == nil && isAutoSubmitted(hdr)) {
			h.log.Warnf("dropping undeliverable auto/bounce message from %q to %s (suppressing bounce)", from, dmcnAddr)
			return nil
		}
		return fmt.Errorf("%w: %s: %v", ErrRecipientNotFound, dmcnAddr, err)
	}

	// 6. Build the DMCN PlaintextMessage from the parsed MIME, preserving the real subject, body
	// content type, attachments, and threading. Fall back to the raw source as the body if the
	// message doesn't parse (or carries no body), so a malformed message is never dropped.
	// The sender is the LEGACY sender, not the bridge. A mail client shows this field, and a
	// libp2p peer ID tells the reader nothing about who wrote to them — worse, it makes every
	// bridged message look like it came from the same correspondent.
	//
	// The bridge signs the message, so the address here is a CLAIM rather than a proof, and the
	// classification record is what backs it: a recipient verifies the bridge's credential and
	// its SPF/DKIM/DMARC verdict for exactly this address before treating the name as meaningful.
	// That is the whole point of the attestation — attributing the mail to the bridge instead
	// would throw away the identity the bridge just went to the trouble of checking.
	msg, err := message.NewPlaintextMessage(
		from,
		dmcnAddr,
		fmt.Sprintf("Bridged message from %s", from),
		"",
		h.bridgeKP.Ed25519Public,
	)
	if err != nil {
		return fmt.Errorf("bridge: compose message: %w", err)
	}
	parsed, perr := parseInboundMIME(rawMsg)
	if perr != nil {
		h.log.Warnf("inbound MIME parse failed for %s, delivering raw source as body: %v", dmcnAddr, perr)
		msg.Body = message.MessageBody{ContentType: "text/plain", Content: rawMsg}
	} else {
		if parsed.Subject != "" {
			msg.Subject = parsed.Subject
		}
		if len(parsed.Body.Content) == 0 && len(parsed.Attachments) == 0 {
			// Parsed but empty (e.g. a non-MIME/headerless payload): keep the raw source as the
			// body rather than delivering an empty message.
			msg.Body = message.MessageBody{ContentType: "text/plain", Content: rawMsg}
		} else {
			msg.Body = parsed.Body
			// Carry the HTML alternative (when the mail was multipart/alternative) so an
			// HTML-capable client can render it; text clients still read msg.Body.
			msg.Alternatives = parsed.Alternatives
		}
		if parsed.HasIDs {
			msg.MessageID = parsed.MessageID
			msg.ThreadID = parsed.ThreadID
			msg.ReplyToID = parsed.ReplyToID
		}
	}

	// Attachments, in a stable order: the signed bridge classification record FIRST (clients read
	// it at index 0), then the exact raw original (so nothing — headers, alternative body parts —
	// is ever lost), then any user attachments parsed from the MIME.
	classHash := crypto.SHA256Hash(classBytes)
	attID, err := crypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("bridge: generate attachment ID: %w", err)
	}
	msg.Attachments = append(msg.Attachments, message.AttachmentRecord{
		AttachmentID: attID,
		Filename:     "classification.bin",
		ContentType:  ClassificationContentType,
		SizeBytes:    uint64(len(classBytes)),
		ContentHash:  classHash,
		Content:      classBytes,
	})
	rawAttID, err := crypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("bridge: generate attachment ID: %w", err)
	}
	msg.Attachments = append(msg.Attachments, message.AttachmentRecord{
		AttachmentID: rawAttID,
		Filename:     "original.eml",
		ContentType:  "message/rfc822",
		SizeBytes:    uint64(len(rawMsg)),
		ContentHash:  crypto.SHA256Hash(rawMsg),
		Content:      rawMsg,
	})
	if perr == nil {
		msg.Attachments = append(msg.Attachments, parsed.Attachments...)
	}

	// 7. Split into an independently-signed header + body and encrypt both under
	// one per-message CEK — the same v2 format clients use, so bridged mail flows
	// through the recipient's mailbox and the identical decrypt path (and the
	// classification stays in MessageContent.Attachments, where clients read it).
	sh, content, err := message.Split(msg, h.bridgeKP.Ed25519Private)
	if err != nil {
		return fmt.Errorf("bridge: split message: %w", err)
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{
		DeviceID:  h.bridgeKP.DeviceID,
		X25519Pub: recipientRec.X25519Public,
	}}, h.bridgeKP.Ed25519Private)
	if err != nil {
		return fmt.Errorf("bridge: encrypt: %w", err)
	}

	// 8. Deliver to the recipient (their relay hints, or our own mailbox if we are
	// the recipient's relay).
	if err := h.deliver(ctx, recipientRec, env); err != nil {
		return fmt.Errorf("bridge: deliver to %s: %w", dmcnAddr, err)
	}

	h.log.Infof("inbound message from %s to %s delivered, hash: %x", from, dmcnAddr, computeEnvelopeHash(env))
	h.audit.Record(AuditEvent{Action: "inbound.deliver", From: from, To: dmcnAddr, SenderIP: senderIP, TrustTier: tier, Success: true})
	return nil
}

// computeEnvelopeHash computes the SHA-256 hash of an envelope's proto bytes.
func computeEnvelopeHash(env *message.EncryptedEnvelope) [32]byte {
	pb := env.ToProto()
	data, err := protoMarshal(pb)
	if err != nil {
		// This should not happen with valid envelopes
		return [32]byte{}
	}
	return crypto.SHA256Hash(data)
}
