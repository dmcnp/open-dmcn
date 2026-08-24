package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/mertenvg/logr/v2"
	"github.com/pires/go-proxyproto"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/relay"
)

// Config holds configuration for the SMTP bridge. In the reference daemon the bridge SHARES the
// daemon's node (a host can't dial itself, and the daemon owns identity provisioning), so this
// config carries only the SMTP↔DMCN translation settings — the libp2p/relay/credential/permit
// knobs live on the daemon's node.Config.
type Config struct {
	SMTPListenAddr string // SMTP listen address (default ":2525")
	BridgeDomain   string // default domain for bridge email addresses
	DMCNDomain     string // default domain for DMCN addresses
	// BridgeAddress is the bridge's libp2p PEER ID — informational, carried into its signed
	// records for display and logs. A bridge has NO DMCN email address: it is infrastructure,
	// and recipients trust it via Credential, not via a directory entry.
	BridgeAddress string
	// Credential is the bridge's root-signed credential (role "bridge"). It travels inside every
	// classification record and delivery receipt the bridge signs, and is the whole basis on
	// which a recipient believes them. Without it the bridge still runs, but everything it
	// asserts is unverifiable, so New warns.
	Credential *identity.Credential
	// Profiles adds extra {bridge↔dmcn} domain pairs a single bridge serves (hosted
	// multi-tenant). The default {BridgeDomain, DMCNDomain} pair is always served too.
	Profiles     []DomainProfile
	PollInterval time.Duration // how often to poll relay for outbound messages
	AuthVerifier AuthVerifier  // nil = use stub
	Deliverer    SMTPDeliverer // nil = use stub

	// AllowedSenderDomains are the DMCN domains whose users may relay outbound
	// mail through this bridge (the open-relay guard). Empty ⇒ only DMCNDomain.
	AllowedSenderDomains []string
	// OutboundRateLimit caps outbound deliveries per sender per hour. 0 ⇒ default.
	OutboundRateLimit int

	// Inbound SMTP abuse controls. 0 ⇒ default for each.
	InboundMaxPerIPPerHour     int // messages per remote IP per hour
	InboundMaxPerSenderPerHour int // messages per envelope sender per hour
	InboundMaxConnections      int // concurrent SMTP connections

	// Inbound SMTP transport security. TLSCertFile+TLSKeyFile enable STARTTLS.
	// RequireTLS rejects mail until the connection is upgraded; ImplicitTLS runs
	// the listener as SMTPS (TLS from the first byte). Require/Implicit need a cert.
	TLSCertFile string
	TLSKeyFile  string
	RequireTLS  bool
	ImplicitTLS bool

	// Audit trail. AuditLogPath appends an append-only JSON-lines audit log of
	// classification/delivery decisions; Audit overrides it with a custom sink.
	AuditLogPath string
	Audit        AuditLog

	// TrustedProxies are CIDRs/IPs of upstream load balancers permitted to send a
	// PROXY-protocol header. When set, the SMTP listener uses that header to learn
	// the real client IP (for SPF + per-IP rate limits); headers from any other
	// source are ignored, so a direct client cannot spoof its address.
	TrustedProxies []string
}

// Bridge is the SMTP-DMCN bridge node.
type Bridge struct {
	node     *node.Node
	bridgeKP *identity.IdentityKeyPair
	inbound  *InboundHandler
	outbound *OutboundHandler
	// dmcnDomain is this bridge's DMCN side, used to address delivery-failure notices.
	dmcnDomain string
	deliver    DeliverFunc // routes finished envelopes (inbound + receipts) to recipients
	smtp       *SMTPServer
	auditFile  *FileAuditLog // non-nil when an audit log file is open; closed on Stop
	poll       time.Duration
	log        logr.Logger
	ctx        context.Context
	cancel     context.CancelFunc
}

// New creates the SMTP bridge over an already-running DMCN node it SHARES with the daemon. The
// caller (the daemon) owns the node's lifecycle and provisions the bridge identity (bridgeKP,
// whose record must be published with BridgeCapability + a routing credential) before calling
// New — the bridge itself neither creates a node nor registers an identity.
func New(ctx context.Context, n *node.Node, bridgeKP *identity.IdentityKeyPair, cfg Config, log ...logr.Logger) (*Bridge, error) {
	var l logr.Logger
	if len(log) > 0 {
		l = log[0]
	} else {
		l = logr.With(logr.M("component", "bridge"))
	}

	ctx, cancel := context.WithCancel(ctx)

	// Defaults
	if cfg.SMTPListenAddr == "" {
		cfg.SMTPListenAddr = ":2525"
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.AuthVerifier == nil {
		cfg.AuthVerifier = &StubAuthVerifier{
			DefaultSPF:   SPFNone,
			DefaultDKIM:  DKIMNone,
			DefaultDMARC: DMARCNone,
		}
	}
	if cfg.Deliverer == nil {
		cfg.Deliverer = &StubSMTPDeliverer{}
	}
	if bridgeKP == nil {
		cancel()
		return nil, fmt.Errorf("bridge: nil bridge key pair (the daemon must provision the bridge identity)")
	}

	// A bridge with no credential can still relay mail, but nothing it signs can be believed:
	// every recipient checking an attestation will reject it for want of one. Say so plainly
	// rather than letting the failure surface later as unexplained distrust in someone's inbox.
	switch {
	case cfg.Credential == nil:
		l.Warnf("no bridge credential: this bridge's signed SPF/DKIM/DMARC verdicts CANNOT be " +
			"verified by recipients and will be treated as untrusted. Issue one with " +
			"`dmcndcli bridge issue` and point DMCND_BRIDGE_CREDENTIAL at it")
	case !cfg.Credential.HasRole(identity.RoleBridge):
		l.Warnf("the configured credential does not carry the %q role — recipients will reject this bridge's attestations", identity.RoleBridge)
	case !bytes.Equal(cfg.Credential.Subject, bridgeKP.Ed25519Public):
		l.Warnf("the configured bridge credential is for a different key than this node's — recipients will reject this bridge's attestations")
	default:
		l.Successf("bridge credential loaded (subject %x…, domain %s)", cfg.Credential.Subject[:6], cfg.Credential.Domain)
	}

	// Audit log: use a caller-supplied sink, else open an append-only file if a
	// path was configured, else a no-op.
	var auditFile *FileAuditLog
	audit := cfg.Audit
	if audit == nil && cfg.AuditLogPath != "" {
		af, err := NewFileAuditLog(cfg.AuditLogPath, bridgeKP.Ed25519Private, l)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("bridge: open audit log: %w", err)
		}
		auditFile = af
		audit = af
		l.Infof("audit log: %s", cfg.AuditLogPath)
	}

	// Deliver finished (split) envelopes the way a client sender would — STORE to
	// the recipient's relay hints so they land in the recipient's mailbox and
	// decrypt via the same path clients use. When the bridge IS the recipient's
	// relay, store locally to avoid a self-dial.
	deliver := makeBridgeDeliver(n, cfg.BridgeAddress, bridgeKP, l)

	inbound := NewInboundHandler(InboundConfig{
		BridgeKP:     bridgeKP,
		BridgeAddr:   cfg.BridgeAddress,
		Credential:   cfg.Credential,
		AuthVerifier: cfg.AuthVerifier,
		Lookup:       n.Registry().Lookup,
		Deliver:      deliver,
		BridgeDomain: cfg.BridgeDomain,
		DMCNDomain:   cfg.DMCNDomain,
		Profiles:     cfg.Profiles,
		Audit:        audit,
		Log:          l,
	})

	outbound := NewOutboundHandler(OutboundConfig{
		BridgeKP:             bridgeKP,
		BridgeAddr:           cfg.BridgeAddress,
		Credential:           cfg.Credential,
		Deliverer:            cfg.Deliverer,
		Lookup:               n.Registry().Lookup,
		BridgeDomain:         cfg.BridgeDomain,
		DMCNDomain:           cfg.DMCNDomain,
		Profiles:             cfg.Profiles,
		AllowedSenderDomains: cfg.AllowedSenderDomains,
		OutboundRateLimit:    cfg.OutboundRateLimit,
		Audit:                audit,
		Log:                  l,
	})

	limits := newInboundLimits(cfg.InboundMaxPerIPPerHour, cfg.InboundMaxPerSenderPerHour, cfg.InboundMaxConnections)
	tlsOpts, err := buildSMTPTLS(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("bridge: smtp tls: %w", err)
	}
	var proxyPolicy proxyproto.ConnPolicyFunc
	if len(cfg.TrustedProxies) > 0 {
		p, perr := proxyproto.ConnLaxWhiteListPolicy(cfg.TrustedProxies)
		if perr != nil {
			cancel()
			return nil, fmt.Errorf("bridge: trusted proxies: %w", perr)
		}
		proxyPolicy = p
		l.Infof("PROXY protocol enabled for trusted proxies: %v", cfg.TrustedProxies)
	}
	smtpSrv := NewSMTPServer(ctx, cfg.SMTPListenAddr, inbound, cfg.BridgeDomain, limits, tlsOpts, proxyPolicy, l)

	return &Bridge{
		node:       n,
		bridgeKP:   bridgeKP,
		inbound:    inbound,
		outbound:   outbound,
		dmcnDomain: cfg.DMCNDomain,
		deliver:    deliver,
		smtp:       smtpSrv,
		auditFile:  auditFile,
		poll:       cfg.PollInterval,
		log:        l,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Start begins the SMTP server and outbound relay polling.
func (b *Bridge) Start() error {
	if err := b.smtp.Start(); err != nil {
		return fmt.Errorf("bridge: start SMTP: %w", err)
	}

	go b.pollLoop()

	b.log.Info("bridge started")
	return nil
}

// pollLoop periodically fetches envelopes from the relay addressed to
// the bridge and processes them for outbound SMTP delivery.
func (b *Bridge) pollLoop() {
	ticker := time.NewTicker(b.poll)
	defer ticker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.processPending()
		}
	}
}

// processPending picks up mail addressed to the bridge and hands it to SMTP.
//
// It reads BOTH of the relay's stores, and has to. A STORE lands in the durable mailbox when the
// envelope is split and this node hosts mailboxes, and in the in-flight store otherwise — and a
// self-hosted daemon is always a mailbox host while browser-composed mail is always split, so
// polling only the in-flight store meant outbound mail sat in the mailbox forever. That went
// unnoticed for as long as nothing could discover the bridge to send to it in the first place.
func (b *Bridge) processPending() {
	rxHex := fmt.Sprintf("%x", b.bridgeKP.X25519Public[:])

	// In-flight store: unsplit envelopes, and anything stored before a mailbox existed.
	store := b.node.Relay().Store()
	envs, hashes := store.Fetch(rxHex)
	for i, env := range envs {
		if b.deliverOne(env) {
			if err := store.Ack(hashes[i]); err != nil {
				b.log.Warnf("ack failed for %x: %v", hashes[i], err)
			}
		}
	}

	// Durable mailbox: the normal path for split envelopes.
	b.processMailbox(b.ctx, rxHex)
}

// processMailbox drains split envelopes addressed to the bridge out of the durable mailbox.
func (b *Bridge) processMailbox(ctx context.Context, rxHex string) {
	mbox := b.node.Relay().Mailbox()
	if mbox == nil {
		return
	}
	entries, _, err := mbox.List(ctx, rxHex, 0, "")
	if err != nil {
		b.log.Warnf("outbound: list mailbox: %v", err)
		return
	}
	for _, entry := range entries {
		var hash [32]byte
		copy(hash[:], entry.Hash)
		body, berr := mbox.GetBody(ctx, rxHex, hash)
		if berr != nil {
			b.log.Warnf("outbound: fetch body %x: %v", hash, berr)
			continue
		}
		env, eerr := relay.EnvelopeFromParts(entry, body)
		if eerr != nil {
			b.log.Warnf("outbound: rebuild envelope %x: %v", hash, eerr)
			continue
		}
		if !b.deliverOne(env) {
			continue
		}
		// Delete only after a delivery attempt that produced a receipt. A message left in
		// place would be retried forever; one deleted on a transport error would be lost.
		if derr := mbox.Delete(ctx, rxHex, hash); derr != nil {
			b.log.Warnf("outbound: delete %x after delivery: %v", hash, derr)
		}
	}
}

// deliverOne runs one envelope through the outbound handler and returns whether it is finished
// with — i.e. whether the bridge reached a verdict it can report, success or failure alike.
func (b *Bridge) deliverOne(env *message.EncryptedEnvelope) bool {
	receipt, deliverErr := b.outbound.HandleEnvelope(b.ctx, env)
	if deliverErr != nil && receipt == nil {
		b.log.Warnf("outbound handling failed: %v", deliverErr)
		return false
	}
	// Only failures come back to the sender. Email has always worked this way — a DSN is for
	// non-delivery, and nobody expects a note confirming each message arrived — and a receipt per
	// successful send would put a second message in the sender's own mailbox for every one they
	// write. The signed success receipt still exists on the audit trail; it just is not mail.
	if shouldNotifySender(receipt) {
		b.sendReceipt(b.ctx, env, receipt)
	}
	return true
}

func (b *Bridge) sendReceipt(ctx context.Context, originalEnv *message.EncryptedEnvelope, receipt *BridgeDeliveryReceipt) {
	// Decrypt the original to learn who to send the receipt to. Uses the same format-agnostic
	// path the delivery itself does — a split envelope (what any browser produces) is not
	// readable by message.Decrypt, so using that here meant the receipt was silently dropped for
	// exactly the messages that were successfully delivered.
	pt, _, err := decryptForBridge(originalEnv, b.bridgeKP)
	if err != nil {
		b.log.Warnf("cannot decrypt for receipt: %v", err)
		return
	}

	// Look up sender to encrypt receipt to them
	senderRec, err := b.node.Lookup(ctx, pt.SenderAddress)
	if err != nil {
		b.log.Warnf("cannot look up sender for receipt: %v", err)
		return
	}

	receiptBytes, err := receipt.Marshal()
	if err != nil {
		b.log.Warnf("marshal receipt: %v", err)
		return
	}

	// From MAILER-DAEMON, not the bridge's peer ID. The bridge has no mailbox by design, and a
	// libp2p peer ID in the From line tells the reader nothing; MAILER-DAEMON is what every mail
	// user has recognised as "the system, not a person" for forty years. It resolves to no DMCN
	// identity, which the client reports honestly as unanchored rather than as a real sender.
	//
	// The body says what happened in full. The signed receipt is still attached — that is the
	// verifiable artifact, and a client can check it against the bridge's credential — but the
	// message has to be readable without parsing an attachment, which "Message delivery receipt
	// attached." was not.
	msg, err := message.NewPlaintextMessage(
		mailerDaemonAddress(b.dmcnDomain),
		pt.SenderAddress,
		fmt.Sprintf("Delivery failed: %s", receipt.RecipientEmail),
		deliveryFailureBody(receipt, pt.Subject),
		b.bridgeKP.Ed25519Public,
	)
	if err != nil {
		b.log.Warnf("compose receipt message: %v", err)
		return
	}

	msg.Attachments = append(msg.Attachments, message.AttachmentRecord{
		Filename:    "receipt.bin",
		ContentType: ReceiptContentType,
		SizeBytes:   uint64(len(receiptBytes)),
		Content:     receiptBytes,
	})

	sh, content, err := message.Split(msg, b.bridgeKP.Ed25519Private)
	if err != nil {
		b.log.Warnf("split receipt: %v", err)
		return
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{
		DeviceID:  b.bridgeKP.DeviceID,
		X25519Pub: senderRec.X25519Public,
	}}, b.bridgeKP.Ed25519Private)
	if err != nil {
		b.log.Warnf("encrypt receipt: %v", err)
		return
	}

	if err := b.deliver(ctx, senderRec, env); err != nil {
		b.log.Warnf("deliver receipt to %s: %v", pt.SenderAddress, err)
		return
	}

	b.log.Debugf("delivery receipt sent to %s", pt.SenderAddress)
}

// Node returns the underlying DMCN node.
func (b *Bridge) Node() *node.Node {
	return b.node
}

// BridgeKeyPair returns the bridge's identity key pair.
func (b *Bridge) BridgeKeyPair() *identity.IdentityKeyPair {
	return b.bridgeKP
}

// Inbound returns the inbound handler for direct testing.
func (b *Bridge) Inbound() *InboundHandler {
	return b.inbound
}

// Outbound returns the outbound handler for direct testing.
func (b *Bridge) Outbound() *OutboundHandler {
	return b.outbound
}

// SMTPAddr returns the SMTP server's listen address.
func (b *Bridge) SMTPAddr() string {
	return b.smtp.Addr()
}

// Stop shuts down the bridge. The DMCN node is owned by the daemon (shared), so it is NOT
// closed here — only the bridge's own SMTP server, poll loop, and audit file.
func (b *Bridge) Stop() error {
	b.cancel()
	b.smtp.Stop()
	if b.auditFile != nil {
		b.auditFile.Close()
	}
	b.log.Info("bridge stopped")
	return nil
}

// makeBridgeDeliver builds the DeliverFunc the bridge uses for both inbound mail
// and delivery receipts. It STOREs the (split) envelope to the recipient's relay
// hints via the relay client — the same path a client sender uses, so the mail
// lands in the recipient's mailbox — falling back to a local store when the
// recipient's relay is the bridge's own node (avoiding a self-dial), or when the
// recipient publishes no relay hints.
func makeBridgeDeliver(n *node.Node, senderAddr string, senderKP *identity.IdentityKeyPair, log logr.Logger) DeliverFunc {
	storeLocal := func(ctx context.Context, env *message.EncryptedEnvelope) error {
		hash := computeEnvelopeHash(env)
		mbox := n.Relay().Mailbox()
		for _, rec := range env.Recipients {
			rxHex := fmt.Sprintf("%x", rec.RecipientXPub[:])
			if mbox != nil && env.IsSplit() {
				if err := mbox.Store(ctx, rxHex, hash, env, time.Now().UTC()); err != nil {
					return err
				}
			} else {
				n.Relay().Store().Store(rxHex, env, hash)
			}
		}
		return nil
	}

	return func(ctx context.Context, recipient *identity.IdentityRecord, env *message.EncryptedEnvelope) error {
		if len(recipient.RelayHints) == 0 {
			return storeLocal(ctx, env) // legacy fallback: recipient fetches from us
		}
		// Routing integrity: only route to hints attested by a verified operator routing
		// credential (RelayHints are unsigned by the owner),
		// so a forged record can't redirect inbound legacy mail to attacker relays.
		if err := n.Registry().VerifyRouting(ctx, recipient); err != nil {
			return fmt.Errorf("recipient routing could not be verified: %w", err)
		}
		self := n.PeerID()
		var lastErr error
		for _, hint := range recipient.RelayHints {
			info, err := node.ParseRelayHint(hint)
			if err != nil {
				lastErr = err
				continue
			}
			if info.ID == self {
				if err := storeLocal(ctx, env); err != nil {
					lastErr = err
					continue
				}
				return nil
			}
			if err := n.ConnectPeer(hint); err != nil {
				lastErr = err
				continue
			}
			if _, err := n.Relay().ClientStoreDurable(ctx, info.ID, senderAddr, senderKP, env); err != nil {
				lastErr = err
				continue
			}
			return nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no usable relay hints")
		}
		return fmt.Errorf("all relay hints failed: %w", lastErr)
	}
}

// buildSMTPTLS turns the bridge's TLS config fields into an smtpTLS, or nil for
// a plaintext listener. RequireTLS/ImplicitTLS without a certificate is an error.
func buildSMTPTLS(cfg Config) (*smtpTLS, error) {
	if cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" {
		if cfg.RequireTLS || cfg.ImplicitTLS {
			return nil, fmt.Errorf("require-tls/implicit-tls set but no tls-cert/tls-key provided")
		}
		return nil, nil // plaintext (dev only)
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, fmt.Errorf("both tls-cert and tls-key are required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	return &smtpTLS{
		config:   &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		require:  cfg.RequireTLS,
		implicit: cfg.ImplicitTLS,
	}, nil
}

// NOTE (open-dmcn): the bridge no longer loads/generates its own keys — the daemon provisions
// the bridge identity (from its seed keystore) and passes the key pair into New. The former
// loadOrGenerateBridgeKeys helper is omitted.

// mailerDaemonAddress is the conventional sender for an automated delivery notice. Reserved in a
// domain's default local-parts, so it cannot be registered by a user and mistaken for one.
func mailerDaemonAddress(dmcnDomain string) string {
	if dmcnDomain == "" {
		return "mailer-daemon@localhost"
	}
	return "mailer-daemon@" + dmcnDomain
}

// deliveryFailureBody renders the human half of a non-delivery notice: what failed, to whom, and
// why, in the terms the sender used rather than the bridge's.
//
// It deliberately does NOT mention the attached receipt. The signed blob rides along for a client
// that wants to verify it, but this reader shows no attachments at all, so pointing at one is
// pointing at something invisible. (The product's client renders a verified delivered/failed badge
// from that attachment instead, and addresses the notice from the legacy recipient so it threads
// with the conversation — a better fit there, and a worse one here, where a notice apparently
// written by the recipient would just be confusing.)
func deliveryFailureBody(receipt *BridgeDeliveryReceipt, originalSubject string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Your message could not be delivered to %s.\n\n", receipt.RecipientEmail)
	if originalSubject != "" {
		fmt.Fprintf(&b, "Subject: %s\n", originalSubject)
	}
	fmt.Fprintf(&b, "Attempted: %s\n\n", receipt.DeliveredAt.Format(time.RFC1123Z))
	if receipt.ErrorDetail != "" {
		fmt.Fprintf(&b, "Reason: %s\n\n", receipt.ErrorDetail)
	}
	b.WriteString("This message left the DMCN network at a bridge and was handed to ordinary " +
		"email, where delivery failed.\n")
	return b.String()
}

// shouldNotifySender reports whether a delivery outcome is worth telling the sender about.
// Failures only — see deliverOne.
func shouldNotifySender(receipt *BridgeDeliveryReceipt) bool {
	return receipt != nil && !receipt.Success
}

// Test hooks for the external test package.
func ShouldNotifySenderForTest(r *BridgeDeliveryReceipt) bool { return shouldNotifySender(r) }
func DeliveryFailureBodyForTest(r *BridgeDeliveryReceipt, subject string) string {
	return deliveryFailureBody(r, subject)
}
func MailerDaemonAddressForTest(domain string) string { return mailerDaemonAddress(domain) }
