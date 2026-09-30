package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	// OutboundMaxAge is how long outbound mail keeps being retried before the bridge gives up and
	// tells the sender. 0 ⇒ DefaultOutboundMaxAge: there is always a lifetime, or a message nothing
	// can deliver — a forgery included — would be kept and retried forever. The node's own in-flight lifetime for
	// everything else is node.Config.TransitMaxAge; the daemon sets both.
	OutboundMaxAge time.Duration
	AuthVerifier   AuthVerifier  // nil = use stub
	Deliverer      SMTPDeliverer // nil = use stub

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
	maxAge     time.Duration // give up on outbound mail this old (always set: see Config.OutboundMaxAge)
	retryMu    sync.Mutex
	retries    map[[32]byte]retryState    // outbound envelopes waiting for their next attempt
	inFlight   map[[32]byte]bool          // outbound envelopes an attempt is running for
	routed     map[[32]byte]routedMessage // where each envelope already opened is going
	pool       *workerPool                // domain workers delivering outbound mail
	handleJob  func(outboundJob)          // what a domain worker does with a job: runJob (a test seam)
	work       sync.WaitGroup             // running domain workers, waited for by Stop
	wake       chan struct{}              // asks the poll loop for a pass before its next tick
	pollDone   chan struct{}              // closed when the poll loop has exited; nil until Start
	log        logr.Logger
	ctx        context.Context
	cancel     context.CancelFunc
}

// DefaultOutboundMaxAge is five days, the lifetime mail servers have long given a message they
// cannot deliver before bouncing it.
const DefaultOutboundMaxAge = 5 * 24 * time.Hour

// keyMismatchLifetime is how long a message whose signing key is not its named sender's is
// retried. The retry is only for a record the bridge holds that a key rotation has since replaced,
// which a lookup sees within minutes; past that it is a forgery, and nobody is told.
const keyMismatchLifetime = time.Hour

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
	if cfg.OutboundMaxAge <= 0 {
		cfg.OutboundMaxAge = DefaultOutboundMaxAge
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

	b := &Bridge{
		node:       n,
		bridgeKP:   bridgeKP,
		inbound:    inbound,
		outbound:   outbound,
		dmcnDomain: cfg.DMCNDomain,
		deliver:    deliver,
		smtp:       smtpSrv,
		auditFile:  auditFile,
		poll:       cfg.PollInterval,
		maxAge:     cfg.OutboundMaxAge,
		retries:    make(map[[32]byte]retryState),
		inFlight:   make(map[[32]byte]bool),
		routed:     make(map[[32]byte]routedMessage),
		pool:       newWorkerPool(),
		wake:       make(chan struct{}, 1),
		log:        l,
		ctx:        ctx,
		cancel:     cancel,
	}
	b.handleJob = b.runJob
	return b, nil
}

// Start begins the SMTP server and outbound relay polling.
func (b *Bridge) Start() error {
	if err := b.smtp.Start(); err != nil {
		return fmt.Errorf("bridge: start SMTP: %w", err)
	}

	b.pollDone = make(chan struct{})
	go b.pollLoop()

	b.log.Info("bridge started")
	return nil
}

// pollLoop periodically fetches envelopes from the relay addressed to
// the bridge and processes them for outbound SMTP delivery.
func (b *Bridge) pollLoop() {
	defer close(b.pollDone)
	ticker := time.NewTicker(b.poll)
	defer ticker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.processPending()
		case <-b.wake:
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
//
// Either way an envelope leaves its store once the bridge is finished with it: delivered, refused
// with a verdict or for good, or given up on after maxAge.
func (b *Bridge) processPending() {
	rxHex := fmt.Sprintf("%x", b.bridgeKP.X25519Public[:])
	var items []outboundItem

	// In-flight store: unsplit envelopes, and anything stored before a mailbox existed.
	store := b.node.Relay().Store()
	for _, q := range store.Queued(rxHex) {
		items = append(items, outboundItem{
			hash:     q.Hash,
			queuedAt: q.StoredAt,
			load:     func() (*message.EncryptedEnvelope, error) { return q.Envelope, nil },
			remove:   func() error { return store.Remove(rxHex, q.Hash) },
		})
	}

	// Durable mailbox: the normal path for split envelopes.
	mailbox, listed := b.mailboxItems(b.ctx, rxHex)
	items = append(items, mailbox...)

	b.dispatch(items, listed)
}

// outboundItem is one queued envelope, from whichever store holds it.
type outboundItem struct {
	hash     [32]byte
	queuedAt time.Time
	load     func() (*message.EncryptedEnvelope, error)
	remove   func() error // deletes it from its store once the bridge is finished with it
}

// mailboxItems lists the split envelopes addressed to the bridge in the durable mailbox, and
// reports false when the listing failed, so the caller does not mistake a failed read for an
// empty mailbox.
func (b *Bridge) mailboxItems(ctx context.Context, rxHex string) ([]outboundItem, bool) {
	mbox := b.node.Relay().Mailbox()
	if mbox == nil {
		return nil, true
	}
	entries, _, err := mbox.List(ctx, rxHex, 0, "", relay.ListOldestFirst)
	if err != nil {
		b.log.Warnf("outbound: list mailbox: %v", err)
		return nil, false
	}
	items := make([]outboundItem, 0, len(entries))
	for _, entry := range entries {
		var hash [32]byte
		copy(hash[:], entry.Hash)
		items = append(items, outboundItem{
			hash:     hash,
			queuedAt: time.Unix(entry.StoredAt, 0),
			load: func() (*message.EncryptedEnvelope, error) {
				body, err := mbox.GetBody(ctx, rxHex, hash)
				if err != nil {
					return nil, fmt.Errorf("fetch body: %w", err)
				}
				return relay.EnvelopeFromParts(entry, body)
			},
			remove: func() error { return mbox.Delete(ctx, rxHex, hash) },
		})
	}
	return items, true
}

// Outbound mail is delivered by a pool of domain workers. A worker takes one recipient domain and
// drains that domain's queue, one message after another, so mail to one domain goes out back to
// back at the speed of its SMTP sessions while a server that hangs holds up only its own queue.
// When the queue is empty the worker stops and goes back to the pool, to be recycled for the
// next domain that has mail.
const (
	outboundWorkers = 8  // domain workers, and so how many domains are delivered to at once
	domainQueueSize = 32 // messages queued on one domain's worker; the rest wait for a later pass
)

// outboundJob is a queued envelope, already opened, on its way to its domain's worker.
type outboundJob struct {
	item   outboundItem
	opened *OpenedMessage
}

// domainWorker drains one recipient domain's queue. The pool makes each once and reuses it.
type domainWorker struct {
	domain string
	jobs   chan outboundJob
}

// workerPool hands recipient domains to domain workers.
type workerPool struct {
	mu     sync.Mutex
	active map[string]*domainWorker // domain → the worker draining its queue
	idle   []*domainWorker          // workers free to take a domain
}

func newWorkerPool() *workerPool {
	p := &workerPool{active: make(map[string]*domainWorker)}
	for i := 0; i < outboundWorkers; i++ {
		p.idle = append(p.idle, &domainWorker{jobs: make(chan outboundJob, domainQueueSize)})
	}
	return p
}

// dispatch routes each queued envelope that is due and not already under way to its domain's
// worker, opening it to learn the domain unless an earlier attempt already did. When items is
// complete — every store listed — it also forgets what it knew of anything that has left the
// queue some other way; after a failed listing that would wipe the schedule of everything backing
// off and send it all out again at once.
func (b *Bridge) dispatch(items []outboundItem, complete bool) {
	if complete {
		queued := make(map[[32]byte]bool, len(items))
		for _, it := range items {
			queued[it.hash] = true
		}
		b.retryMu.Lock()
		for hash := range b.retries {
			if !queued[hash] {
				delete(b.retries, hash)
			}
		}
		var gone []routedMessage
		for hash, r := range b.routed {
			if !queued[hash] {
				delete(b.routed, hash)
				gone = append(gone, r)
			}
		}
		b.retryMu.Unlock()
		for _, r := range gone {
			b.outbound.retrying.forget(r.msgID, r.recipient)
		}
	}

	for _, it := range items {
		if b.ctx.Err() != nil {
			return
		}
		if !b.claim(it.hash) {
			continue
		}
		// A message whose lifetime is up is given up on here if no worker can take it, rather than
		// left to wait until the relay drops it without a word to anyone.
		expired := time.Since(it.queuedAt) >= b.maxAge
		// A message whose domain has no room right now is not opened again just to find that out.
		if domain, ok := b.knownDomain(it.hash); ok && !expired && !b.hasRoom(domain) {
			b.release(it.hash)
			continue
		}
		opened, ok := b.open(it)
		if !ok {
			b.release(it.hash)
			continue
		}
		domain := domainOf(opened.Plaintext.RecipientAddress)
		b.note(it.hash, opened, domain)
		if b.enqueue(domain, outboundJob{item: it, opened: opened}) {
			continue
		}
		if expired {
			b.expireUnsent(it, opened)
		}
		b.release(it.hash) // no worker free, or its queue is full: a later pass takes it
	}
}

// expireUnsent gives up on a message whose lifetime ran out while it waited for a worker, and
// tells its sender just as a worker giving up would have.
func (b *Bridge) expireUnsent(it outboundItem, opened *OpenedMessage) {
	b.log.Warnf("outbound: giving up on %x after %s: no worker was free to send it", it.hash, b.maxAge)
	a := b.outbound.Expire(b.ctx, opened)
	receipt := b.outbound.Abandon(a, b.maxAge)
	b.finished(it.hash)
	if shouldNotifySender(receipt) {
		b.sendReceipt(b.ctx, opened.Plaintext, a.Sender, receipt)
	}
	if err := it.remove(); err != nil {
		b.log.Warnf("outbound: delete %x: %v", it.hash, err)
	}
}

// open loads and opens a queued envelope. It reports false for one that cannot go to a worker
// now: one that could not be loaded (retried on the schedule, dropped once past maxAge) or opened
// (dropped at once — no retry decrypts it).
func (b *Bridge) open(it outboundItem) (*OpenedMessage, bool) {
	env, err := it.load()
	if err != nil {
		// Something the bridge cannot even load — a mailbox entry whose body is gone — gets the
		// same schedule and lifetime as anything else it cannot deliver, and then goes. Nobody
		// can be told: nothing names a sender.
		if time.Since(it.queuedAt) < b.maxAge {
			b.log.Warnf("outbound: load %x, next attempt at %s: %v", it.hash, b.deferRetry(it.hash).Format(time.RFC3339), err)
			return nil, false
		}
		b.log.Warnf("outbound: giving up on %x after %s: %v", it.hash, b.maxAge, err)
		b.drop(it, &OutboundAttempt{Err: fmt.Errorf("load queued envelope: %w", err), Retry: true})
		return nil, false
	}
	opened, err := b.outbound.Open(env)
	if err != nil {
		b.log.Warnf("outbound: dropping a message no retry can deliver: %v", err)
		b.drop(it, &OutboundAttempt{Err: err})
		return nil, false
	}
	return opened, true
}

// drop ends an envelope the bridge could not get as far as a worker: audited, never notified.
func (b *Bridge) drop(it outboundItem, a *OutboundAttempt) {
	b.outbound.Abandon(a, b.maxAge)
	b.finished(it.hash)
	if err := it.remove(); err != nil {
		b.log.Warnf("outbound: delete %x: %v", it.hash, err)
	}
}

// hasRoom reports whether a message for domain could be queued now: its worker's queue has space,
// or it has no worker and one is free.
func (b *Bridge) hasRoom(domain string) bool {
	p := b.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if w, ok := p.active[domain]; ok {
		return len(w.jobs) < cap(w.jobs)
	}
	return len(p.idle) > 0
}

// enqueue puts a job on its domain's worker, taking a worker from the pool and starting it when
// the domain has none. It never blocks: false means no worker is free or the queue is full.
func (b *Bridge) enqueue(domain string, job outboundJob) bool {
	p := b.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	w, ok := p.active[domain]
	if !ok {
		if len(p.idle) == 0 {
			return false
		}
		w = p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		w.domain = domain
		p.active[domain] = w
		b.work.Add(1)
		go b.runWorker(w)
	}
	select {
	case w.jobs <- job:
		return true
	default:
		return false
	}
}

// runWorker drains a domain worker's queue, then returns the worker to the pool. The queue is
// checked for emptiness under the pool's lock, the same lock enqueue sends under, so nothing
// can be queued on a worker that has just decided to stop.
func (b *Bridge) runWorker(w *domainWorker) {
	defer b.work.Done()
	p := b.pool
	for {
		select {
		case <-b.ctx.Done():
			// Stopping: what is still queued stays in its store for the restart.
			for len(w.jobs) > 0 {
				b.release((<-w.jobs).item.hash)
			}
			return
		case job := <-w.jobs:
			b.handleJob(job)
			continue
		default:
		}
		p.mu.Lock()
		if len(w.jobs) > 0 {
			p.mu.Unlock()
			continue
		}
		delete(p.active, w.domain)
		w.domain = ""
		p.idle = append(p.idle, w)
		p.mu.Unlock()
		b.nudge() // a worker is free: mail waiting for one need not wait for the next poll
		return
	}
}

// runJob makes one attempt at a job and deletes the envelope from its store if the bridge is
// finished with it.
func (b *Bridge) runJob(job outboundJob) {
	defer b.release(job.item.hash)
	if !b.attempt(job.opened, job.item.hash, job.item.queuedAt) {
		return
	}
	if err := job.item.remove(); err != nil {
		b.log.Warnf("outbound: delete %x after delivery: %v", job.item.hash, err)
	}
}

// nudge asks the poll loop for a pass now rather than at its next tick.
func (b *Bridge) nudge() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// Retry schedule for outbound mail that reached no verdict: a minute, then doubling, then every
// six hours until maxAge — the shape mail servers have long used, which is quick about a moment's
// trouble and patient with a server that stays down.
const (
	firstRetry = time.Minute
	maxRetry   = 6 * time.Hour
)

// retryState is where one envelope is on the retry schedule.
type retryState struct {
	attempts int
	next     time.Time
}

// claim marks an envelope as under way if it is due and no attempt at it is running, and reports
// whether it did. The schedule is in memory, so a restart tries everything once more straight
// away.
func (b *Bridge) claim(hash [32]byte) bool {
	b.retryMu.Lock()
	defer b.retryMu.Unlock()
	if b.inFlight[hash] {
		return false
	}
	if r, ok := b.retries[hash]; ok && time.Now().Before(r.next) {
		return false
	}
	b.inFlight[hash] = true
	return true
}

// release ends the claim on an envelope.
func (b *Bridge) release(hash [32]byte) {
	b.retryMu.Lock()
	defer b.retryMu.Unlock()
	delete(b.inFlight, hash)
}

// deferRetry moves an envelope one step along the retry schedule and returns when it is next due.
func (b *Bridge) deferRetry(hash [32]byte) time.Time {
	b.retryMu.Lock()
	defer b.retryMu.Unlock()
	r := b.retries[hash]
	wait := maxRetry
	if r.attempts < 20 { // past that the doubling has long since passed the cap
		wait = min(firstRetry<<r.attempts, maxRetry)
	}
	r.attempts++
	r.next = time.Now().Add(wait)
	b.retries[hash] = r
	return r.next
}

// finished drops an envelope from the retry schedule.
func (b *Bridge) finished(hash [32]byte) {
	b.retryMu.Lock()
	defer b.retryMu.Unlock()
	delete(b.retries, hash)
	delete(b.routed, hash)
}

// routedMessage is what the bridge learned about a queued envelope by opening it.
type routedMessage struct {
	domain    string   // recipient domain, whose worker it goes to
	msgID     [16]byte // with recipient, the key the outbound handler remembers it under
	recipient string
}

// note remembers where an opened envelope is going, so a later pass need not open it again.
func (b *Bridge) note(hash [32]byte, opened *OpenedMessage, domain string) {
	b.retryMu.Lock()
	defer b.retryMu.Unlock()
	b.routed[hash] = routedMessage{domain: domain, msgID: opened.Plaintext.MessageID, recipient: opened.Plaintext.RecipientAddress}
}

// knownDomain is the recipient domain of an envelope, once a pass has opened it.
func (b *Bridge) knownDomain(hash [32]byte) (string, bool) {
	b.retryMu.Lock()
	defer b.retryMu.Unlock()
	r, ok := b.routed[hash]
	return r.domain, ok
}

// attempt sends one opened envelope through the outbound handler and reports whether the bridge
// is finished with it, so the caller can delete it. Finished means a verdict it can act on,
// success or failure alike, or a refusal no retry can change. Anything else is retried on the
// schedule until it has been queued for maxAge, and then given up on. Deleted on a transport
// error it would be lost; kept for good it would be retried, and stored, forever.
func (b *Bridge) attempt(opened *OpenedMessage, hash [32]byte, queuedAt time.Time) bool {
	a := b.outbound.Send(b.ctx, opened)
	receipt := a.Receipt
	if receipt == nil && a.Err != nil {
		lifetime := b.maxAge
		if errors.Is(a.Err, ErrSenderKeyMismatch) {
			lifetime = min(lifetime, keyMismatchLifetime)
		}
		switch {
		case b.ctx.Err() != nil:
			// Stopping: the attempt was cut short, not answered. It stays queued for the restart
			// rather than being dropped, or given up on with a notice nothing could now send.
			return false
		case !a.Retry:
			b.log.Warnf("outbound: dropping a message no retry can deliver: %v", a.Err)
		case time.Since(queuedAt) < lifetime:
			b.log.Warnf("outbound handling failed, next attempt at %s: %v", b.deferRetry(hash).Format(time.RFC3339), a.Err)
			return false
		default:
			b.log.Warnf("outbound: giving up after %s: %v", lifetime, a.Err)
		}
		receipt = b.outbound.Abandon(a, b.maxAge)
	}
	b.finished(hash)
	// Only failures come back to the sender. Email has always worked this way — a DSN is for
	// non-delivery, and nobody expects a note confirming each message arrived — and a receipt per
	// successful send would put a second message in the sender's own mailbox for every one they
	// write. The signed success receipt still exists on the audit trail; it just is not mail.
	// There is a receipt only when the sender was verified, so a.Sender is their checked record.
	if shouldNotifySender(receipt) {
		b.sendReceipt(b.ctx, a.Plaintext, a.Sender, receipt)
	}
	return true
}

// sendReceipt tells the sender of pt how their message fared, sealed to senderRec — the record
// its signing key was checked against when it was handled.
func (b *Bridge) sendReceipt(ctx context.Context, pt *message.PlaintextMessage, senderRec *identity.IdentityRecord, receipt *BridgeDeliveryReceipt) {
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
	// Let the poll loop and any running attempt finish before the shared node is used by anyone
	// else or goes away.
	if b.pollDone != nil {
		<-b.pollDone
	}
	b.work.Wait()
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
// lands in the recipient's mailbox — storing locally when the recipient's relay is
// the bridge's own node (avoiding a self-dial). A recipient with no relay hints has
// no mailbox and is refused: the bridge does not hold mail for it.
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
			return fmt.Errorf("%w: %s", ErrRecipientHasNoMailbox, recipient.Address)
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
