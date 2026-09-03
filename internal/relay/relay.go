package relay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	ds "github.com/ipfs/go-datastore"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/mailfilter"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/peerpolicy"
	"dmcn.dev/open-dmcn/internal/registry"
)

// Clients (the web backend, the CLI commands) and server nodes deliberately
// speak this same single protocol: clients use the relay's Client* methods to
// STORE/FETCH, and the web client syncs its mailbox over plain REST polling — no
// push/presence/subscribe semantics are needed, so a separate /dmcn/client
// protocol was evaluated and intentionally not added. A client just runs
// node-side in ClientOnly mode (no relay server handlers).
const (
	// ProtocolID is the libp2p protocol identifier for the relay service.
	ProtocolID = protocol.ID("/dmcn/relay/1.0.0")
	// PeersProtocolID is the libp2p protocol identifier for cluster peer discovery.
	PeersProtocolID = protocol.ID("/dmcn/peers/1.0.0")
	// maxMessageSize is the maximum size of a single protocol frame (4 MB). This
	// is a per-frame DoS bound; whole messages may exceed it via chunked transfer.
	maxMessageSize = 4 * 1024 * 1024
	// bodyChunkSize is the size of each streamed body chunk frame (well under the
	// per-frame cap).
	bodyChunkSize = 1024 * 1024
	// maxBodySize bounds a whole reassembled message body (DoS ceiling; real
	// per-user quota policy is a later mailbox concern).
	maxBodySize = 64 * 1024 * 1024
	// defaultRateLimit is the PoC rate limit (100 STORE ops/hr/identity).
	defaultRateLimit = 100
)

var (
	// ErrUnregisteredSender is returned when a STORE sender is not in the registry.
	ErrUnregisteredSender = errors.New("relay: sender identity not registered")
	// ErrRateLimited is returned when a sender exceeds the rate limit.
	ErrRateLimited = errors.New("relay: rate limit exceeded")
	// ErrAuthFailed is returned when FETCH authentication fails.
	ErrAuthFailed = errors.New("relay: authentication failed")
	// ErrQuotaExceeded is returned when a personal-KV PUT would exceed the account's storage quota.
	ErrQuotaExceeded = errors.New("relay: personal storage quota exceeded")
	// ErrMailboxFull is returned when a STORE would push the recipient's mailbox over the
	// account's total-storage cap. It is retryable in the SMTP sense (the Phase 2 bridge maps
	// it to a 452 tempfail): the sender should back off while the recipient frees space.
	ErrMailboxFull = errors.New("relay: recipient mailbox full")
	// ErrAccessSuspended / ErrAccessClosed are returned by a FETCH when the account's access
	// entitlement puts it in the suspended (reads locked, inbound still accepted) or closed
	// (terminal) mode. The web surfaces these distinctly so the user sees why mail won't load.
	ErrAccessSuspended = errors.New("relay: account access suspended")
	ErrAccessClosed    = errors.New("relay: account access closed")
)

// LookupFunc looks up an identity in the registry by address.
// This abstraction allows testing without a live fleet.
type LookupFunc func(ctx context.Context, address string) (*identity.IdentityRecord, error)

// FetchPolicyFunc reports whether an address is allowed to read its mailbox under
// domain policy (e.g. requires a valid domain countersignature). A non-nil error
// rejects the FETCH/LIST/BODY/DELETE. nil = no policy enforcement.
type FetchPolicyFunc func(ctx context.Context, rec *identity.IdentityRecord) error

// MailFilterStore holds recipients' sealed mail-filter blobs, keyed by the
// recipient's X25519 public key (hex-encoded — the same key mailboxes are keyed
// on). A nil blob with nil error means "no filter configured" (allow everything).
// The blob is dual-sealed to the owner key and this relay's mailbox key, so the
// relay can decrypt it to enforce silently at STORE while the owner edits it across
// devices (P5 of the domain-anchored federation plan). GetFilter is on the hot
// STORE path; PutFilter/DeleteFilter back the owner-facing (FETCH-authenticated) API.
type MailFilterStore interface {
	GetFilter(ctx context.Context, recipientHex string) (*message.SealedBlob, error)
	PutFilter(ctx context.Context, recipientHex string, blob *message.SealedBlob) error
	DeleteFilter(ctx context.Context, recipientHex string) error
}

// SenderVerifierFunc reports whether a sender's identity is domain-verified
// (TierDomainDNS), for the recipient allow-list "admit any verified sender" option.
type SenderVerifierFunc func(ctx context.Context, rec *identity.IdentityRecord) bool

// Relay implements the DMCN relay protocol over libp2p streams.
type Relay struct {
	host        host.Host
	lookup      LookupFunc
	fetchPolicy FetchPolicyFunc // optional; gates reads under domain policy
	// storeVouchExempt (optional) admits an un-vouched sender's STORE for the
	// countersign-request bootstrap (pending sender -> own domain's inbox).
	storeVouchExempt StoreVouchExemptFunc
	store            *MessageStore
	mailbox          *MailboxStore // durable mailbox; nil unless this node opts into the role
	accounts         *AccountStore // node-local self-encrypted set of hosted addresses; nil unless mailbox role
	capacityBytes    uint64        // configured mailbox capacity (0 = unset/unbounded), reported via STAT
	draining         atomic.Bool   // drain mode: reject new STORE/assignments, non-candidate in STAT
	limiter          *RateLimiter
	peerLimiter      *RateLimiter // pre-auth per-peer throttle: bounds junk-request volume from non-credentialed peers (connections are open)

	// Recipient mail filtering (P5). filterStore yields a recipient's sealed
	// block/allow list; the relay opens it with its mailbox key (filterPriv/Pub) and
	// silently drops STOREs from filtered senders. senderVerified resolves the
	// allow-list "any verified sender" option. All nil ⇒ filtering disabled.
	filterStore    MailFilterStore
	filterPriv     [32]byte
	filterPub      [32]byte
	senderVerified SenderVerifierFunc

	// Personal KV store: the owner-only, zero-knowledge storage substrate behind
	// Sent, read/unread+labels, contacts and settings. Values are sealed to the
	// owner alone, so the relay only ever holds ciphertext. nil ⇒ disabled.
	personalKv *PersistentKvStore
	// storageQuota is the node-default per-account TOTAL durable-storage cap in bytes
	// (0 = unbounded): mail (MailboxStore) + personal-KV bytes together, keyed on the
	// same recipient X25519 hex. It is the free/trial storage floor; a RoleQuota grant
	// raises it per account (see effectiveQuota). Enforced on both the mail STORE and the
	// KV PUT path so the settled storage tiers (4/25/100 GiB) are one honest total.
	storageQuota uint64
	// replicates reports whether an owner's domain opts into mailbox replication
	// (PolicyReplicateMailbox). When true, an accepted KV write/delete is fanned out
	// to the owner's other RelayHints via MailboxKvInject. nil ⇒ no replication.
	replicates func(context.Context, string) bool

	// records is the node's local authoritative copy of the self-authenticating records it
	// serves for the domains it hosts (identity records, DARs, address-removal tombstones,
	// credential blocklists, its fleet roster). It backs the fleet-resolution ops: a reader
	// bootstraps from DNS seeds, fetches these here, and verifies each against the domain's DNS
	// fingerprint. nil ⇒ this node serves no records (a pure client / relay).
	records *RecordStore
	// darAnchor (optional) verifies a domain's DAR fingerprint against its _dmcn DNS anchor; consulted
	// only when accepting a domain's FIRST DAR (later ones chain to the stored root).
	darAnchor func(context.Context, string, string) error

	log        logr.Logger
	startTime  time.Time
	version    string
	peers      []string
	peerPolicy peerpolicy.Policy          // optional; gates relay + peer-discovery streams by peer
	peerRole   func(peer.ID, string) bool // optional; reports whether an admitted peer holds a credential role (handoff-inject gating: the fleet 'node' role)
	peerGrant  func(peer.ID, string) bool // optional; reports whether an admitted peer holds a FLEET grant (operator op gating: routing/admin), chaining to the config operator root

	// Onion forwarding (SPEC.md §6). When onionEnabled, the relay peels and
	// forwards/delivers OnionForward packets with onionPriv. onionSeen dedups
	// recently-forwarded packets by hash.
	onionEnabled bool
	onionPriv    [32]byte
	onionMu      sync.Mutex
	onionSeen    map[[32]byte]time.Time

	// onionRequired caches, per hosted mailbox (keyed by recipient X25519 hex),
	// whether that mailbox demands onion-routed delivery. Learned at FETCH time
	// from the recipient's own (authentic, self-signed) IdentityRecord. Used to
	// reject a direct STORE to an onion-required mailbox (server-side enforcement;
	// see SPEC.md §6). isRelayPeer distinguishes an onion arrival that came
	// through the mesh (predecessor is a relay) from a 1-hop self-delivery
	// (predecessor is a client) — nil ⇒ trust the onion path (lenient).
	onionRequired sync.Map // string(x25519 hex) -> bool
	isRelayPeer   func(peer.ID) bool
	// onionPolicy computes a recipient's effective RequireOnion (mailbox flag OR
	// domain DAR policy). nil ⇒ fall back to the record's own flag.
	onionPolicy func(context.Context, *identity.IdentityRecord) bool
	// onionJitter, when > 0, adds a random per-hop delay in [0, onionJitter) before
	// forwarding/delivering, to blur timing correlation. 0 ⇒ no delay.
	onionJitter time.Duration

	mu      sync.Mutex
	started bool
}

// onionArrival describes how an envelope reached acceptEnvelope, so RequireOnion
// can be enforced: only an onion arrival through the relay mesh satisfies it.
type onionArrival int

const (
	arrivalDirect      onionArrival = iota // direct client STORE
	arrivalOnionRelay                      // onion DELIVER whose predecessor is a relay
	arrivalOnionClient                     // onion DELIVER whose predecessor is a client (1-hop)
)

// New creates a new Relay service.
func New(h host.Host, lookup LookupFunc, opts ...Option) *Relay {
	cfg := &relayOptions{
		rateLimit: defaultRateLimit,
		version:   "dmcn-node/0.1.0",
	}
	for _, o := range opts {
		o(cfg)
	}

	log := logr.With(logr.M("component", "relay"))

	// In-flight message store: durable when a datastore is configured, else
	// in-memory. A load failure falls back to in-memory rather than refusing to
	// start (mail still flows; durability is degraded and logged).
	store := NewMessageStore()
	if cfg.messageStore != nil {
		if ps, err := NewPersistentMessageStore(cfg.messageStore, log); err != nil {
			log.Errorf("relay: persistent message store load failed, using in-memory: %v", err)
		} else {
			store = ps
		}
	}

	r := &Relay{
		host:             h,
		lookup:           lookup,
		fetchPolicy:      cfg.fetchPolicy,
		storeVouchExempt: cfg.storeVouchExempt,
		store:            store,
		mailbox:          cfg.mailbox,
		accounts:         cfg.accounts,
		capacityBytes:    cfg.capacityBytes,
		limiter:          NewRateLimiter(cfg.rateLimit),
		peerLimiter:      NewRateLimiter(cfg.rateLimit * 10),
		log:              log,
		version:          cfg.version,
		peers:            cfg.peers,
		peerPolicy:       cfg.peerPolicy,
		peerRole:         cfg.peerRole,
		peerGrant:        cfg.peerGrant,
		onionEnabled:     cfg.onionEnabled,
		onionPriv:        cfg.onionKey,
		onionSeen:        make(map[[32]byte]time.Time),
		isRelayPeer:      cfg.isRelayPeer,
		onionPolicy:      cfg.onionPolicy,
		onionJitter:      cfg.onionJitter,

		filterStore:    cfg.filterStore,
		filterPriv:     cfg.filterPriv,
		filterPub:      cfg.filterPub,
		senderVerified: cfg.senderVerified,

		personalKv:   cfg.personalKv,
		storageQuota: cfg.storageQuota,
		replicates:   cfg.replicates,
		records:      cfg.records,
		darAnchor:    cfg.darAnchor,
	}
	return r
}

type relayOptions struct {
	rateLimit        int
	version          string
	peers            []string
	mailbox          *MailboxStore
	accounts         *AccountStore
	capacityBytes    uint64
	messageStore     ds.Batching
	fetchPolicy      FetchPolicyFunc
	storeVouchExempt StoreVouchExemptFunc
	peerPolicy       peerpolicy.Policy
	peerRole         func(peer.ID, string) bool
	peerGrant        func(peer.ID, string) bool
	onionEnabled     bool
	onionKey         [32]byte
	isRelayPeer      func(peer.ID) bool
	onionPolicy      func(context.Context, *identity.IdentityRecord) bool
	onionJitter      time.Duration

	filterStore    MailFilterStore
	filterPriv     [32]byte
	filterPub      [32]byte
	senderVerified SenderVerifierFunc

	personalKv   *PersistentKvStore
	storageQuota uint64
	replicates   func(context.Context, string) bool
	records      *RecordStore
	darAnchor    func(context.Context, string, string) error
}

// WithMailboxFilter enables recipient mail filtering: filterStore yields each
// recipient's sealed block/allow list, mailboxPriv/Pub is the relay's X25519 key
// that opens it, and senderVerified (optional) resolves the allow-list "any
// verified sender" option. Filtered senders are silently dropped at STORE.
func WithMailboxFilter(store MailFilterStore, mailboxPriv, mailboxPub [32]byte, senderVerified SenderVerifierFunc) Option {
	return func(o *relayOptions) {
		o.filterStore = store
		o.filterPriv = mailboxPriv
		o.filterPub = mailboxPub
		o.senderVerified = senderVerified
	}
}

// WithPersonalKv enables the owner-only personal KV store (Sent, read/unread+labels,
// contacts, settings). Values are sealed to the owner alone, so the relay only ever
// holds ciphertext. Owner auth reuses the FETCH challenge like the other MailboxOps.
func WithPersonalKv(store *PersistentKvStore) Option {
	return func(o *relayOptions) {
		o.personalKv = store
	}
}

// WithStorageQuota sets the node-default per-account TOTAL durable-storage cap in
// bytes — mail (MailboxStore) + personal-KV together, keyed on the recipient X25519
// hex; 0 (default) is unbounded. It is the free/trial storage floor; a per-account
// RoleQuota grant raises it (effectiveQuota). Enforced on both the mail STORE and the
// KV PUT path so the settled storage tiers are one honest total.
func WithStorageQuota(bytes uint64) Option {
	return func(o *relayOptions) {
		o.storageQuota = bytes
	}
}

// WithPersonalKvQuota is a deprecated alias for WithStorageQuota. The node-default cap
// now governs total account storage (mail + personal-KV), not just the KV store; use
// WithStorageQuota. Retained so existing callers keep compiling.
func WithPersonalKvQuota(bytes uint64) Option { return WithStorageQuota(bytes) }

// WithReplicatePolicy enables personal-KV write replication. When check(ctx, address)
// reports the owner's domain replicates mailboxes (PolicyReplicateMailbox), an accepted
// KV PUT/DELETE is fanned out to the owner's other RelayHints via MailboxKvInject, so
// every home relay carries the owner's storage. nil (default) = no replication.
func WithReplicatePolicy(check func(context.Context, string) bool) Option {
	return func(o *relayOptions) {
		o.replicates = check
	}
}

// WithRecordStore installs the node's local authoritative record store, enabling the
// fleet-resolution ops (get identity/DAR/roster/removal/blocklist) that serve self-authenticating
// records over libp2p. nil (default) ⇒ the node answers those ops as "not found".
func WithRecordStore(rs *RecordStore) Option {
	return func(o *relayOptions) {
		o.records = rs
	}
}

// WithDARAnchor supplies the DNS verifier consulted when the node accepts a domain's FIRST
// DomainAuthorityRecord. A DAR is self-anchoring — its signature only proves the key it carries
// signed it — so a genesis write has no prior root key to chain to; anchoring the fingerprint in
// _dmcn.<domain> is what makes the first root the domain owner's. Later DARs are admitted by
// root-key continuity instead, which needs no DNS.
//
// The check is fail-closed. node.New always wires it (the registry's verifier: real DNS, the
// node's static _dmcn map, or the dev stub), so a dev setup passes by the stub, not by leniency.
// nil = no genesis anchoring (a relay built without a node, e.g. in tests).
func WithDARAnchor(f func(ctx context.Context, domain, fingerprint string) error) Option {
	return func(o *relayOptions) {
		o.darAnchor = f
	}
}

// WithFetchPolicy gates mailbox reads (FETCH/LIST/BODY/DELETE) on a domain-policy
// check evaluated after the recipient lookup. nil = no enforcement.
func WithFetchPolicy(check FetchPolicyFunc) Option {
	return func(o *relayOptions) {
		o.fetchPolicy = check
	}
}

// StoreVouchExemptFunc reports whether an envelope from an un-vouched sender may
// be stored anyway. The one intended exemption is the countersign-request
// bootstrap: a pending sender petitioning its OWN domain's countersign inbox
// (SPEC.md §2, PolicyAllowRequests) — without it, a sender that needs the
// domain's vouch could never ask for it.
type StoreVouchExemptFunc func(ctx context.Context, senderRec *identity.IdentityRecord, env *message.EncryptedEnvelope) bool

// WithStoreVouchExemption installs the un-vouched-sender STORE exemption check.
// nil = no exemption (un-vouched senders are always refused where their domain
// demands vouching).
func WithStoreVouchExemption(check StoreVouchExemptFunc) Option {
	return func(o *relayOptions) {
		o.storeVouchExempt = check
	}
}

// Option configures a Relay.
type Option func(*relayOptions)

// WithRateLimit sets the maximum STORE operations per hour per sender.
func WithRateLimit(maxPerHour int) Option {
	return func(o *relayOptions) {
		o.rateLimit = maxPerHour
	}
}

// WithPeers sets the infra/cluster peers for this relay node.
func WithPeers(peers []string) Option {
	return func(o *relayOptions) {
		o.peers = peers
	}
}

// WithPeerPolicy gates relay and peer-discovery streams to federated peers
// (defense-in-depth behind the connection gater). nil = allow all callers.
func WithPeerPolicy(p peerpolicy.Policy) Option {
	return func(o *relayOptions) {
		o.peerPolicy = p
	}
}

// WithPeerRoleCheck supplies a predicate reporting whether an admitted peer holds a given
// credential role (from the /dmcn/join handshake). Used to gate the relay→relay handoff
// inject (node role). nil = no role info, so role-gated ops are refused.
func WithPeerRoleCheck(f func(peer.ID, string) bool) Option {
	return func(o *relayOptions) {
		o.peerRole = f
	}
}

// WithPeerGrantCheck supplies a predicate reporting whether an admitted peer holds a given
// FLEET grant (an action it may perform). Used to gate fleet/operator ops: RequestMailbox
// requires 'routing'; SetDrain/Accounts/MailboxHandoff require 'admin'. The grant must come
// from an operator-rooted (config-anchored) credential verified at /dmcn/join — a domain
// credential's grant can never satisfy it (fleet ops are not domain-scoped). nil = no grant
// info, so grant-gated ops are refused (fail closed).
func WithPeerGrantCheck(f func(peer.ID, string) bool) Option {
	return func(o *relayOptions) {
		o.peerGrant = f
	}
}

// WithMailbox opts this node into the durable mailbox role: split STOREs are
// persisted (hold-until-deleted) and served via the LIST/BODY/DELETE ops.
func WithMailbox(m *MailboxStore) Option {
	return func(o *relayOptions) {
		o.mailbox = m
	}
}

// WithAccountStore wires the node-local self-encrypted account list (the set of addresses
// this node hosts), populated at assignment + authenticated FETCH and exported to authority
// callers for drain. Mailbox-role nodes only.
func WithAccountStore(a *AccountStore) Option {
	return func(o *relayOptions) {
		o.accounts = a
	}
}

// WithMailboxCapacity sets the relay's mailbox capacity in bytes, reported via the STAT
// op so load-aware placement can weight by free space. 0 = unset (treated as unbounded).
func WithMailboxCapacity(bytes uint64) Option {
	return func(o *relayOptions) {
		o.capacityBytes = bytes
	}
}

// WithMessageDatastore makes the relay's in-flight message store durable, backed
// by the given (borrowed) datastore. Queued envelopes and their delivery status
// survive a restart. nil ⇒ in-memory only.
func WithMessageDatastore(d ds.Batching) Option {
	return func(o *relayOptions) {
		o.messageStore = d
	}
}

// WithOnionKey enables onion-forward participation: the relay will peel and
// forward/deliver OnionForward packets using priv (its onion X25519 key). Omit it
// (or run client-only / --no-onion-relay) to refuse onion forwarding.
func WithOnionKey(priv [32]byte) Option {
	return func(o *relayOptions) {
		o.onionKey = priv
		o.onionEnabled = true
	}
}

// WithOnionPeerCheck supplies a predicate that reports whether a peer is a
// participating relay (e.g. it publishes a RelayDescriptor). Used to tell a
// genuine mesh-forwarded onion delivery from a 1-hop self-delivery by a client,
// so RequireOnion cannot be bypassed by wrapping a direct send in one layer.
func WithOnionPeerCheck(fn func(peer.ID) bool) Option {
	return func(o *relayOptions) {
		o.isRelayPeer = fn
	}
}

// WithOnionPolicy supplies the effective-RequireOnion resolver (mailbox flag OR
// domain DAR policy), consulted at FETCH to learn a hosted mailbox's policy.
func WithOnionPolicy(fn func(context.Context, *identity.IdentityRecord) bool) Option {
	return func(o *relayOptions) {
		o.onionPolicy = fn
	}
}

// WithOnionJitter sets the maximum random per-hop delay applied before forwarding
// or delivering an onion packet (timing-correlation hardening). 0 disables it.
func WithOnionJitter(max time.Duration) Option {
	return func(o *relayOptions) {
		o.onionJitter = max
	}
}

// Mailbox returns the durable mailbox store, or nil if this node is not a
// mailbox. Exposed for direct access in tests and by the node (e.g. bridge).
func (r *Relay) Mailbox() *MailboxStore {
	return r.mailbox
}

// Start registers the stream handler and begins serving relay operations.
func (r *Relay) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.started = true
	r.startTime = time.Now()
	r.host.SetStreamHandler(ProtocolID, r.handleStream)
	r.host.SetStreamHandler(PeersProtocolID, r.handlePeers)
	r.log.Info("relay started")
}

// Stop removes the stream handler.
func (r *Relay) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return
	}
	r.started = false
	r.host.RemoveStreamHandler(ProtocolID)
	r.host.RemoveStreamHandler(PeersProtocolID)
	r.log.Info("relay stopped")
}

// Store returns the underlying message store for direct access in tests.
func (r *Relay) Store() *MessageStore {
	return r.store
}

// peerAllowed reports whether a remote peer may use this relay. A nil policy
// (e.g. direct relay.New callers and tests) allows everyone.
func (r *Relay) peerAllowed(p peer.ID) bool {
	return r.peerPolicy == nil || r.peerPolicy.Allow(peerpolicy.PeerContext{ID: p})
}

// peerHasRole reports whether the admitted peer holds the given credential role. With no
// role checker wired it returns false, so role-gated ops are refused (fail closed).
func (r *Relay) peerHasRole(p peer.ID, role string) bool {
	return r.peerRole != nil && r.peerRole(p, role)
}

// peerHasFleetGrant reports whether the admitted peer holds the given FLEET grant — an
// operator-rooted (config-anchored) capability for a fleet op. With no checker wired it
// returns false (fail closed). Fleet grants are NOT domain-scoped: a domain credential's
// grant can never authorize a fleet op (the confused-deputy guard).
func (r *Relay) peerHasFleetGrant(p peer.ID, grant string) bool {
	return r.peerGrant != nil && r.peerGrant(p, grant)
}

// handleStream processes an incoming relay protocol stream.
func (r *Relay) handleStream(s network.Stream) {
	defer s.Close()
	caller := s.Conn().RemotePeer()

	// Pre-auth throttle: with connections open (no hard gater), cap request volume from
	// NON-credentialed peers to bound junk-request amplification on the message-gated ops
	// (e.g. rotating-sender STOREs that each trigger a registry lookup). Credential-admitted
	// peers (web/relays) are accountable and exempt; the per-sender STORE limiter still applies.
	if !r.peerAllowed(caller) && !r.peerLimiter.Allow(caller.String()) {
		return
	}

	req, err := readRequest(s)
	if err != nil {
		return
	}

	var resp *dmcnpb.RelayResponse

	// Per-op gating (credentials gate ACTIONS, at the action's layer). There is NO blanket
	// connection gate: an action carries its own credential where it lives.
	switch {
	// Message-authenticated mail ops — the credential rides IN the message: STORE carries the
	// sender signature + the sender's domain-authority gate; FETCH uses challenge-response. They
	// are NOT connection-gated, so a credentialed sender from any fleet, or an end-user client,
	// may use them (the relay routes a message because the message holds the proof).
	case req.GetStore() != nil:
		resp = r.handleStore(caller, req.GetStore())
	case req.GetStoreInit() != nil:
		r.handleStoreInit(s, req.GetStoreInit()) // self-gates: sender sig (store) or node role (handoff inject)
		return                                   // reads body chunks + writes its own response
	case req.GetFetchInit() != nil:
		r.handleFetch(s, req.GetFetchInit()) // self-gates: challenge-response
		return                               // handleFetch writes its own responses
	case req.GetPing() != nil:
		resp = r.handlePing()

	// Connection-credential-gated ops — relay-to-relay actions that carry no message-borne
	// credential, so they require a credential-admitted (federated) peer. (The operator
	// surface — drain, stat, quota/access, handoffs, send counters — rides its own
	// /dmcn/operate protocol; see operate.go.)
	case req.GetAck() != nil:
		resp = r.gateFederated(caller, func() *dmcnpb.RelayResponse { return r.handleAck(req.GetAck()) })
	case req.GetOnionForward() != nil:
		resp = r.gateFederated(caller, func() *dmcnpb.RelayResponse { return r.handleOnion(caller, req.GetOnionForward()) })

	// Fleet-resolution ops — public, unauthenticated reads of self-authenticating records.
	// The reader verifies each against the domain's DNS fingerprint, so the serving node is
	// untrusted transport; the pre-auth throttle above bounds junk-request volume.
	case req.GetGetIdentity() != nil:
		resp = r.handleGetIdentity(req.GetGetIdentity())
	case req.GetGetDar() != nil:
		resp = r.handleGetDAR(req.GetGetDar())
	case req.GetGetFleetRoster() != nil:
		resp = r.handleGetFleetRoster(req.GetGetFleetRoster())
	case req.GetGetRemoval() != nil:
		resp = r.handleGetRemoval(req.GetGetRemoval())
	case req.GetGetBlocklist() != nil:
		resp = r.handleGetBlocklist(req.GetGetBlocklist())
	case req.GetPutRecord() != nil:
		// Self-gates: identity pushes require the 'routing' grant; all kinds are re-verified.
		resp = r.handlePutRecord(caller, req.GetPutRecord())
	case req.GetGetRelayDescriptor() != nil:
		resp = r.handleGetRelayDescriptor(req.GetGetRelayDescriptor())
	default:
		resp = errorResponse("INVALID_REQUEST", "unknown request type")
	}

	writeResponse(s, resp)
}

// gateFederated runs op only for a credential-admitted (federated) peer — used for
// relay-to-relay / operator / info ops that carry no message-borne credential. With no peer
// policy wired (direct relay.New callers / tests) it allows everyone.
func (r *Relay) gateFederated(caller peer.ID, op func() *dmcnpb.RelayResponse) *dmcnpb.RelayResponse {
	if !r.peerAllowed(caller) {
		return errorResponse("UNAUTHORIZED", "requires a credential-admitted federated peer")
	}
	return op()
}

// handleStore processes a single-frame STORE request (whole envelope in one frame).
func (r *Relay) handleStore(_ peer.ID, req *dmcnpb.StoreRequest) *dmcnpb.RelayResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	env, err := message.EncryptedEnvelopeFromProto(req.Envelope)
	if err != nil {
		return errorResponse("INVALID_ENVELOPE", fmt.Sprintf("invalid envelope: %v", err))
	}
	// The signed hash is over the canonical envelope marshaling; req.Envelope is
	// exactly what the client marshaled, so re-marshal it for the hash.
	envBytes, err := proto.Marshal(req.Envelope)
	if err != nil {
		return errorResponse("INTERNAL_ERROR", "failed to marshal envelope")
	}
	envHash := crypto.SHA256Hash(envBytes)

	return r.acceptEnvelope(ctx, req.SenderAddress, req.SenderSignature, env, envHash, arrivalDirect)
}

// requiresOnion reports whether the mailbox at the given recipient X25519 hex has
// been observed (at FETCH) to require onion-routed delivery.
func (r *Relay) requiresOnion(recipientHex string) bool {
	v, ok := r.onionRequired.Load(recipientHex)
	return ok && v.(bool)
}

// handleStoreInit processes a chunked durable STORE: this frame carries the
// envelope minus the body, then the body bytes stream in as raw chunks. The whole
// message may exceed the per-frame cap.
func (r *Relay) handleStoreInit(s network.Stream, init *dmcnpb.StoreInit) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	body, err := readChunked(s, init.BodyTotalSize)
	if err != nil {
		writeResponse(s, errorResponse("INVALID_REQUEST", fmt.Sprintf("read body chunks: %v", err)))
		return
	}

	// Reassemble the full envelope via the proto round-trip so its canonical
	// marshaling (and thus hash) is identical to what the sender signed.
	env, err := message.EncryptedEnvelopeFromProto(&dmcnpb.EncryptedEnvelope{
		Version:            init.Version,
		MessageId:          init.MessageId,
		CreatedAt:          init.CreatedAt,
		Recipients:         init.Recipients,
		EncryptedHeader:    init.EncryptedHeader,
		HeaderNonce:        init.HeaderNonce,
		HeaderTag:          init.HeaderTag,
		HeaderSizeClass:    init.HeaderSizeClass,
		EncryptedBody:      body,
		BodyNonce:          init.BodyNonce,
		BodyTag:            init.BodyTag,
		BodySizeClass:      init.BodySizeClass,
		BodyContentAddress: init.BodyContentAddress, // must match the sender-signed envelope hash
	})
	if err != nil {
		writeResponse(s, errorResponse("INVALID_ENVELOPE", fmt.Sprintf("invalid envelope: %v", err)))
		return
	}
	envBytes, err := proto.Marshal(env.ToProto())
	if err != nil {
		writeResponse(s, errorResponse("INTERNAL_ERROR", "failed to marshal envelope"))
		return
	}
	envHash := crypto.SHA256Hash(envBytes)

	// (The relay→relay drain handoff variant moved to the /dmcn/operate protocol's
	// handoff_store op — see operate.go handleHandoffStore.)
	writeResponse(s, r.acceptEnvelope(ctx, init.SenderAddress, init.SenderSignature, env, envHash, arrivalDirect))
}

// acceptEnvelope rate-limits, verifies the sender is registered, checks the
// signature over the envelope hash, and persists the envelope for every recipient.
// A mailbox node durably stores split (header/body) envelopes hold-until-deleted;
// everything else uses the transient in-memory store served by FETCH.
func (r *Relay) acceptEnvelope(ctx context.Context, senderAddr string, senderSig []byte, env *message.EncryptedEnvelope, envHash [32]byte, arrival onionArrival) *dmcnpb.RelayResponse {
	if r.draining.Load() {
		return errorResponse("NODE_DRAINING", "node is draining; not accepting new mail")
	}
	if !r.limiter.Allow(senderAddr) {
		r.log.Warnf("STORE rate limited for sender %s", senderAddr)
		return errorResponse("RATE_LIMITED", ErrRateLimited.Error())
	}

	// RequireOnion enforcement: a mailbox that demands onion-routed delivery only
	// accepts envelopes that arrived through the relay mesh. A direct STORE, or a
	// 1-hop "onion" whose predecessor is a client, is rejected.
	if arrival != arrivalOnionRelay {
		for _, rec := range env.Recipients {
			if r.requiresOnion(fmt.Sprintf("%x", rec.RecipientXPub[:])) {
				r.log.Warnf("STORE rejected: recipient requires onion-routed delivery")
				return errorResponse("ONION_REQUIRED", "recipient requires onion-routed delivery")
			}
		}
	}

	senderRec, err := r.resolveIdentity(ctx, senderAddr)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			r.log.Warnf("STORE rejected: unregistered sender %s", senderAddr)
			return errorResponse("UNREGISTERED_SENDER", ErrUnregisteredSender.Error())
		}
		return errorResponse("LOOKUP_FAILED", fmt.Sprintf("sender lookup: %v", err))
	}

	if err := crypto.Verify(senderRec.Ed25519Public, envHash[:], senderSig); err != nil {
		r.log.Warnf("STORE rejected: invalid signature from %s", senderAddr)
		return errorResponse("INVALID_SIGNATURE", "sender signature verification failed")
	}

	// Sender-authority gate (the message-borne credential for STORE): the sender must be USABLE
	// under its domain policy — on a require-countersign domain that means a valid domain
	// countersignature (its address-credential chain to the DNS-anchored DAR). This closes
	// "any self-registered key can inject mail": an un-vouched sender is refused where its
	// domain demands vouching. fetchPolicy is the address-usability check (registry.AddressUsable),
	// generic over the address; nil (direct callers/tests) ⇒ skipped (fail open).
	// The single carve-out is the countersign-request bootstrap (storeVouchExempt):
	// a pending sender may petition its OWN domain's countersign inbox — the very
	// message that earns it the vouch — where the DAR opens the request channel.
	if r.fetchPolicy != nil {
		if perr := r.fetchPolicy(ctx, senderRec); perr != nil {
			if r.storeVouchExempt == nil || !r.storeVouchExempt(ctx, senderRec, env) {
				r.log.Warnf("STORE rejected: sender %s not vouched under its domain policy: %v", senderAddr, perr)
				return errorResponse("SENDER_NOT_VOUCHED", perr.Error())
			}
			r.log.Infof("STORE from pending sender %s admitted to its domain countersign inbox", senderAddr)
		}
	}

	// Keyless body-integrity check: if the envelope carries a recognized cleartext
	// content address, the body bytes must hash to it. Fails open for pre-feature
	// senders (no/unknown address); body_hash + AEAD remain authoritative end-to-end.
	if err := env.VerifyBodyContentAddress(); err != nil {
		r.log.Warnf("STORE rejected: body content-address mismatch from %s", senderAddr)
		return errorResponse("INVALID_ENVELOPE", "body does not match content address")
	}

	durable := r.mailbox != nil && env.IsSplit()
	// Anti-free-ride (fleet-managed mailbox node): only store for recipients this node was
	// actually assigned (a reservation recorded the rxHex). A recipient with no account record
	// is not homed here, so the fleet can't be used to host a domain it never permitted. The
	// recipient's domain is not in the (sealed) envelope, so this presence check stands in for a
	// domain check WITHOUT a global rxHex→address index — the reservation already permit-gated
	// the domain.
	// NOTE (open-dmcn): the fleet free-ride guard (accept STORE only for recipients this
	// relay was permit-assigned) is a fleet-ownership surface, omitted here — a single
	// self-hosted domain serves its own recipients.
	stored := 0
	for _, rec := range env.Recipients {
		addr := fmt.Sprintf("%x", rec.RecipientXPub[:])
		// Recipient filtering: silently drop (no store, but the sender still gets a
		// normal ACK) when this recipient's block/allow policy rejects the
		// authenticated sender. Fail-open on any decode/read error — a filter problem
		// must never lose legitimate mail.
		if r.filterStore != nil && !r.recipientPermits(ctx, addr, senderAddr, senderRec) {
			r.log.Debugf("STORE silently dropped for recipient %s: sender %s filtered", addr[:8], senderAddr)
			continue
		}
		if durable {
			// Total-storage quota: reject when this message would push the recipient's
			// account (mail + personal-KV) over its cap. Unlike filtering, an over-quota
			// STORE must NOT be silently dropped — the sender is told MAILBOX_FULL (a
			// retryable "come back once space frees up"; the Phase 2 bridge maps it to a
			// 452 tempfail). The check counts the whole incoming entry against current
			// usage, so it can only reject sooner (safe). Sends route per recipient to
			// that recipient's home, so in practice one homed recipient is stored here.
			if quota := r.effectiveQuota(ctx, addr); quota > 0 {
				used, uerr := r.accountUsedBytes(ctx, addr)
				if uerr != nil {
					r.log.Errorf("STORE quota check failed for recipient %s…: %v", addr[:min(8, len(addr))], uerr)
					return errorResponse("STORAGE_FAILED", "storage quota check failed")
				}
				if used+mailboxEntrySize(env) > quota {
					r.log.Warnf("STORE rejected: recipient %s… mailbox full (used=%d cap=%d)", addr[:min(8, len(addr))], used, quota)
					return errorResponse("MAILBOX_FULL", ErrMailboxFull.Error())
				}
			}
			if err := r.mailbox.Store(ctx, addr, envHash, env, time.Now().UTC()); err != nil {
				r.log.Errorf("STORE mailbox persist failed for %s: %v", senderAddr, err)
				return errorResponse("STORAGE_FAILED", "failed to persist message")
			}
		} else {
			r.store.Store(addr, env, envHash)
		}
		stored++
	}
	_ = stored

	r.log.Debugf("STORE accepted from %s, hash %x, %d recipients, durable=%t", senderAddr, envHash[:8], len(env.Recipients), durable)

	return &dmcnpb.RelayResponse{
		Response: &dmcnpb.RelayResponse_Store{
			Store: &dmcnpb.StoreResponse{EnvelopeHash: envHash[:]},
		},
	}
}

// StoreLocal accepts a pre-signed envelope in-process, running the same verification and
// routing as a STORE arriving over a relay stream (sender registered, signature over the
// envelope hash, body content-address, onion policy, durable-vs-transient routing) — it just
// skips the libp2p round-trip. It exists for the single-binary reference daemon, whose webmail
// backend shares this node rather than dialing it (a libp2p host cannot dial itself). The
// returned hash is the envelope's; errors are mapped to sentinels (ErrMailboxFull, …) like the
// client STORE path so callers can errors.Is them.
func (r *Relay) StoreLocal(ctx context.Context, senderAddr string, senderSig []byte, env *message.EncryptedEnvelope) ([32]byte, error) {
	envBytes, err := proto.Marshal(env.ToProto())
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store local: marshal envelope: %w", err)
	}
	envHash := crypto.SHA256Hash(envBytes)
	resp := r.acceptEnvelope(ctx, senderAddr, senderSig, env, envHash, arrivalDirect)
	if err := storeRespError(resp); err != nil {
		return envHash, err
	}
	return envHash, nil
}

// recipientPermits reports whether the recipient's sealed mail-filter policy
// admits the authenticated sender. It fails OPEN (permits) on a missing filter or
// any decode/decrypt error, so a filter fault never drops legitimate mail.
func (r *Relay) recipientPermits(ctx context.Context, recipientHex, senderAddr string, senderRec *identity.IdentityRecord) bool {
	blob, err := r.filterStore.GetFilter(ctx, recipientHex)
	if err != nil || blob == nil {
		return true
	}
	pt, err := message.OpenSealed(blob, r.filterPriv, r.filterPub)
	if err != nil {
		r.log.Warnf("mail filter: cannot open list for %s: %v", recipientHex[:8], err)
		return true
	}
	list, err := mailfilter.Unmarshal(pt)
	if err != nil {
		r.log.Warnf("mail filter: malformed list for %s: %v", recipientHex[:8], err)
		return true
	}
	verified := false
	senderKeyHex := ""
	if senderRec != nil {
		if r.senderVerified != nil {
			verified = r.senderVerified(ctx, senderRec)
		}
		senderKeyHex = fmt.Sprintf("%x", senderRec.Ed25519Public)
	}
	return list.Permits(senderAddr, senderKeyHex, verified)
}

// handleFetch processes a FETCH request with challenge-response auth.
func (r *Relay) handleFetch(s network.Stream, init *dmcnpb.FetchInit) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Lookup recipient in registry
	rec, err := r.resolveIdentity(ctx, init.Address)
	if err != nil {
		writeResponse(s, errorResponse("LOOKUP_FAILED", fmt.Sprintf("identity not found: %v", err)))
		return
	}

	// Learn this mailbox's onion-delivery policy from its authentic (self-signed)
	// record — the binding of X25519 key ⇒ RequireOnion is from the record, not the
	// (as-yet-unauthenticated) requester, so caching it here is safe. Effective
	// policy is the mailbox flag OR the domain DAR policy. Used to reject direct
	// STOREs to onion-required mailboxes.
	requireOnion := rec.RequireOnion
	if r.onionPolicy != nil {
		requireOnion = r.onionPolicy(ctx, rec)
	}
	r.onionRequired.Store(fmt.Sprintf("%x", rec.X25519Public[:]), requireOnion)

	// 1a. Domain-policy gate: a require-countersign domain's address must carry a
	// valid countersignature before its mailbox can be read. Mail addressed to it
	// is still accepted (STORE is not gated) and released once countersigned.
	if r.fetchPolicy != nil {
		if perr := r.fetchPolicy(ctx, rec); perr != nil {
			r.log.Debugf("FETCH denied by policy for %s: %v", init.Address, perr)
			writeResponse(s, errorResponse("POLICY_PENDING", perr.Error()))
			return
		}
	}

	// 2. Generate challenge nonce
	nonce, err := crypto.RandomBytes(32)
	if err != nil {
		writeResponse(s, errorResponse("INTERNAL_ERROR", "failed to generate challenge"))
		return
	}

	// 3. Send challenge
	challenge := &dmcnpb.RelayResponse{
		Response: &dmcnpb.RelayResponse_FetchChallenge{
			FetchChallenge: &dmcnpb.FetchChallenge{
				Nonce: nonce,
			},
		},
	}
	if err := writeResponse(s, challenge); err != nil {
		return
	}

	// 4. Read the authenticated request: either a transient FETCH proof or a
	// durable mailbox op. Both carry the signed challenge nonce.
	authReq, err := readRequest(s)
	if err != nil {
		return
	}

	// Helper: verify the signed nonce proves control of the recipient identity.
	verify := func(sig []byte) bool {
		return crypto.Verify(rec.Ed25519Public, nonce, sig) == nil
	}

	switch {
	case authReq.GetFetchProof() != nil:
		proof := authReq.GetFetchProof()
		if !verify(proof.Signature) {
			r.log.Warnf("FETCH auth failed for %s", init.Address)
			writeResponse(s, errorResponse("AUTH_FAILED", ErrAuthFailed.Error()))
			return
		}
		addr := fmt.Sprintf("%x", rec.X25519Public[:])
		envs, hashes := r.store.Fetch(addr)
		pbEnvs := make([]*dmcnpb.EncryptedEnvelope, len(envs))
		pbHashes := make([][]byte, len(hashes))
		for i, env := range envs {
			pbEnvs[i] = env.ToProto()
			hash := hashes[i]
			pbHashes[i] = hash[:]
		}
		r.log.Debugf("FETCH returning %d envelope(s) for %s", len(envs), init.Address)
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_Fetch{
				Fetch: &dmcnpb.FetchResponse{Envelopes: pbEnvs, EnvelopeHashes: pbHashes},
			},
		})

	case authReq.GetMailboxOp() != nil:
		op := authReq.GetMailboxOp()
		if !verify(op.Signature) {
			r.log.Warnf("mailbox auth failed for %s", init.Address)
			writeResponse(s, errorResponse("AUTH_FAILED", ErrAuthFailed.Error()))
			return
		}
		if r.mailbox == nil {
			writeResponse(s, errorResponse("MAILBOX_UNAVAILABLE", "this node is not a mailbox"))
			return
		}
		// Backstop: record this proven address (and its rxHex, for the STORE free-ride
		// guard) in the account list — covers records created before the assignment
		// handshake existed. Authenticated above.
		if r.accounts != nil {
			if err := r.accounts.Record(ctx, init.Address); err != nil {
				r.log.Debugf("account backstop record failed for %s: %v", init.Address, err)
			}
			if err := r.accounts.RecordHex(ctx, fmt.Sprintf("%x", rec.X25519Public[:])); err != nil {
				r.log.Debugf("account hex backstop record failed for %s: %v", init.Address, err)
			}
		}
		r.handleMailboxOp(ctx, s, fmt.Sprintf("%x", rec.X25519Public[:]), init.Address, rec, op)

	default:
		writeResponse(s, errorResponse("INVALID_REQUEST", "expected fetch proof or mailbox op"))
	}
}

// handleMailboxOp dispatches a verified mailbox operation against the recipient's
// durable mailbox (rxHex = hex of the recipient X25519 public key), writing the
// response(s) directly to the stream. BODY streams a header frame followed by raw
// body chunks; LIST and DELETE write a single response frame.
func (r *Relay) handleMailboxOp(ctx context.Context, s network.Stream, rxHex, address string, rec *identity.IdentityRecord, op *dmcnpb.MailboxOp) {
	switch {
	case op.GetList() != nil:
		lo := op.GetList()
		entries, next, err := r.mailbox.List(ctx, rxHex, int(lo.Limit), string(lo.Cursor))
		if err != nil {
			r.log.Errorf("mailbox LIST failed for %s: %v", address, err)
			writeResponse(s, errorResponse("STORAGE_FAILED", "list failed"))
			return
		}
		r.log.Debugf("mailbox LIST returning %d entries for %s", len(entries), address)
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxList{
				MailboxList: &dmcnpb.MailboxListResponse{Entries: entries, NextCursor: []byte(next)},
			},
		})

	case op.GetBody() != nil:
		var hash [32]byte
		copy(hash[:], op.GetBody().Hash)
		body, err := r.mailbox.GetBody(ctx, rxHex, hash)
		if errors.Is(err, ErrEnvelopeNotFound) {
			writeResponse(s, errorResponse("NOT_FOUND", ErrEnvelopeNotFound.Error()))
			return
		}
		if err != nil {
			r.log.Errorf("mailbox BODY failed for %s: %v", address, err)
			writeResponse(s, errorResponse("STORAGE_FAILED", "body fetch failed"))
			return
		}
		// Header frame, then the body bytes as raw chunks.
		if err := writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxBodyHeader{
				MailboxBodyHeader: &dmcnpb.MailboxBodyHeader{
					BodyNonce:     body.BodyNonce,
					BodyTag:       body.BodyTag,
					BodySizeClass: body.BodySizeClass,
					BodyTotalSize: uint64(len(body.EncryptedBody)),
				},
			},
		}); err != nil {
			return
		}
		if err := writeChunked(s, body.EncryptedBody); err != nil {
			r.log.Debugf("mailbox BODY chunk write failed for %s: %v", address, err)
		}

	case op.GetDelete() != nil:
		var hash [32]byte
		copy(hash[:], op.GetDelete().Hash)
		if err := r.mailbox.Delete(ctx, rxHex, hash); err != nil {
			r.log.Errorf("mailbox DELETE failed for %s: %v", address, err)
			writeResponse(s, errorResponse("STORAGE_FAILED", "delete failed"))
			return
		}
		r.log.Debugf("mailbox DELETE %x for %s", hash[:8], address)
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxDelete{
				MailboxDelete: &dmcnpb.MailboxDeleteResponse{Success: true},
			},
		})

	// --- Personal storage. Owner auth is the same FETCH challenge that guards the mail ops
	// above, so these need no separate authentication: reaching here already proves control of
	// the recipient identity, and every op is scoped to that owner's rxHex.
	//
	// The work lives on Relay (KvGet/KvPut/...) rather than here, because the daemon's webmail
	// reaches the same operations in-process without opening a stream. One implementation, two
	// transports — otherwise the quota check exists on one path and not the other.
	case op.GetKvGet() != nil:
		sealed, version, found, err := r.KvGet(ctx, rxHex, op.GetKvGet().Key)
		if err != nil {
			writeResponse(s, kvErrorResponse(r, address, "GET", err))
			return
		}
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxKvGet{
				MailboxKvGet: &dmcnpb.MailboxKvGetResponse{Found: found, Sealed: sealed, Version: version},
			},
		})

	case op.GetKvPut() != nil:
		put := op.GetKvPut()
		version, err := r.KvPut(ctx, rxHex, put.Key, put.Sealed, put.ExpectedVersion)
		if err != nil {
			writeResponse(s, kvErrorResponse(r, address, "PUT", err))
			return
		}
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxKvPut{
				MailboxKvPut: &dmcnpb.MailboxKvPutResponse{Success: true, Version: version},
			},
		})

	case op.GetKvList() != nil:
		lo := op.GetKvList()
		items, next, err := r.KvList(ctx, rxHex, lo.Prefix, int(lo.Limit), string(lo.Cursor), lo.Values)
		if err != nil {
			writeResponse(s, kvErrorResponse(r, address, "LIST", err))
			return
		}
		out := make([]*dmcnpb.MailboxKvItem, 0, len(items))
		for _, it := range items {
			out = append(out, &dmcnpb.MailboxKvItem{Key: it.Key, Sealed: it.Sealed, Version: it.Version})
		}
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxKvList{
				MailboxKvList: &dmcnpb.MailboxKvListResponse{Items: out, NextCursor: []byte(next)},
			},
		})

	case op.GetKvDelete() != nil:
		if err := r.KvDelete(ctx, rxHex, op.GetKvDelete().Key); err != nil {
			writeResponse(s, kvErrorResponse(r, address, "DELETE", err))
			return
		}
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxKvDelete{
				MailboxKvDelete: &dmcnpb.MailboxKvDeleteResponse{Success: true},
			},
		})

	case op.GetKvStat() != nil:
		used, quota, count, err := r.KvStat(ctx, rxHex)
		if err != nil {
			writeResponse(s, kvErrorResponse(r, address, "STAT", err))
			return
		}
		writeResponse(s, &dmcnpb.RelayResponse{
			Response: &dmcnpb.RelayResponse_MailboxKvStat{
				MailboxKvStat: &dmcnpb.MailboxKvStatResponse{UsedBytes: used, QuotaBytes: quota, Count: count},
			},
		})

	default:
		writeResponse(s, errorResponse("INVALID_REQUEST", "unknown mailbox op"))
	}
}

// ErrKvUnsupported is returned when this relay hosts no personal storage. A relay may serve mail
// without it (no datastore, or a deliberately minimal node), and a client that sees it can fall
// back to local-only state rather than treating the mailbox as broken.
var ErrKvUnsupported = errors.New("relay: this relay does not host personal storage")

// KvGet reads one of the owner's sealed blobs.
func (r *Relay) KvGet(ctx context.Context, rxHex, key string) (sealed []byte, version uint64, found bool, err error) {
	if r.personalKv == nil {
		return nil, 0, false, ErrKvUnsupported
	}
	return r.personalKv.Get(ctx, rxHex, key)
}

// KvPut writes one sealed blob, enforcing the account's storage cap.
//
// The cap is the account's TOTAL — mail plus personal storage — the same figure the mail STORE
// path enforces, so the two cannot be used to exceed it separately. Usage is measured before the
// write and the new blob added to it, which over-counts an overwrite slightly; that is safe,
// since it can only refuse sooner. The coupling is worth knowing: a full mailbox blocks personal
// writes too, and the way out is deleting mail or KV entries.
func (r *Relay) KvPut(ctx context.Context, rxHex, key string, sealed []byte, expectedVersion uint64) (uint64, error) {
	if r.personalKv == nil {
		return 0, ErrKvUnsupported
	}
	if quota := r.effectiveQuota(ctx, rxHex); quota > 0 {
		used, err := r.accountUsedBytes(ctx, rxHex)
		if err != nil {
			return 0, fmt.Errorf("relay: personal kv quota check: %w", err)
		}
		if used+uint64(len(sealed)) > quota {
			return 0, ErrQuotaExceeded
		}
	}
	return r.personalKv.Put(ctx, rxHex, key, sealed, expectedVersion)
}

// KvList pages the owner's keys under a namespace prefix.
func (r *Relay) KvList(ctx context.Context, rxHex, prefix string, limit int, cursor string, values bool) ([]KvItem, string, error) {
	if r.personalKv == nil {
		return nil, "", ErrKvUnsupported
	}
	return r.personalKv.List(ctx, rxHex, prefix, limit, cursor, values)
}

// KvDelete removes one blob. Idempotent, and a malformed key is treated as absent rather than an
// error — a client deleting something that cannot exist has already got what it wanted.
func (r *Relay) KvDelete(ctx context.Context, rxHex, key string) error {
	if r.personalKv == nil {
		return ErrKvUnsupported
	}
	if err := r.personalKv.Delete(ctx, rxHex, key); err != nil && !errors.Is(err, ErrKvBadKey) {
		return err
	}
	return nil
}

// KvStat reports the owner's storage occupancy and the cap that applies.
//
// used is the COMBINED mail + personal figure the quota is actually enforced against, not the KV
// half alone: a meter showing room while writes are refused is worse than no meter.
func (r *Relay) KvStat(ctx context.Context, rxHex string) (used, quota, count uint64, err error) {
	if r.personalKv == nil {
		return 0, 0, 0, ErrKvUnsupported
	}
	count, _, err = r.personalKv.StatsOwner(ctx, rxHex)
	if err != nil {
		return 0, 0, 0, err
	}
	if used, err = r.accountUsedBytes(ctx, rxHex); err != nil {
		return 0, 0, 0, err
	}
	return used, r.effectiveQuota(ctx, rxHex), count, nil
}

// kvErrorResponse maps a KV error to a wire response, logging only the ones that indicate a
// server-side problem — a bad key or a version conflict is the client's to handle.
func kvErrorResponse(r *Relay, address, op string, err error) *dmcnpb.RelayResponse {
	switch {
	case errors.Is(err, ErrKvUnsupported):
		return errorResponse("UNSUPPORTED", err.Error())
	case errors.Is(err, ErrKvBadKey):
		return errorResponse("INVALID_REQUEST", "invalid storage key")
	case errors.Is(err, ErrKvConflict):
		return errorResponse("CONFLICT", "storage version conflict")
	case errors.Is(err, ErrQuotaExceeded):
		return errorResponse("QUOTA_EXCEEDED", "personal storage quota exceeded")
	default:
		r.log.Errorf("personal KV %s failed for %s: %v", op, address, err)
		return errorResponse("STORAGE_FAILED", "storage operation failed")
	}
}

// effectiveQuota is the TOTAL durable-storage byte cap that applies to one account
// (keyed by recipient X25519 hex) — mail (MailboxStore) + personal-KV together. A
// self-hosting operator sets one node-wide default for every account it serves; 0 means
// unbounded. Per-account entitlements are an extension concern and are deliberately not
// part of the core protocol (see SPEC.md §8).
func (r *Relay) effectiveQuota(_ context.Context, _ string) uint64 {
	return r.storageQuota
}

// accountUsedBytes reports an account's total durable-storage occupancy in bytes —
// mail (MailboxStore) + personal-KV — both keyed on the recipient X25519 hex. It is the
// figure effectiveQuota is enforced against on the mail STORE and KV PUT paths, and is
// reported to the owner via the storage STAT. A nil sub-store contributes 0.
func (r *Relay) accountUsedBytes(ctx context.Context, rxHex string) (uint64, error) {
	var total uint64
	if r.mailbox != nil {
		_, mailBytes, err := r.mailbox.StatsOwner(ctx, rxHex)
		if err != nil {
			return 0, err
		}
		total += mailBytes
	}
	if r.personalKv != nil {
		_, kvBytes, err := r.personalKv.StatsOwner(ctx, rxHex)
		if err != nil {
			return 0, err
		}
		total += kvBytes
	}
	return total, nil
}

// handleAck processes an ACK request.
func (r *Relay) handleAck(req *dmcnpb.AckRequest) *dmcnpb.RelayResponse {
	var hash [32]byte
	copy(hash[:], req.EnvelopeHash)

	if err := r.store.Ack(hash); err != nil {
		return errorResponse("NOT_FOUND", err.Error())
	}

	return &dmcnpb.RelayResponse{
		Response: &dmcnpb.RelayResponse_Ack{
			Ack: &dmcnpb.AckResponse{Success: true},
		},
	}
}

// handlePing processes a PING request.
func (r *Relay) handlePing() *dmcnpb.RelayResponse {
	uptime := time.Since(r.startTime)
	return &dmcnpb.RelayResponse{
		Response: &dmcnpb.RelayResponse_Ping{
			Ping: &dmcnpb.PingResponse{
				Version:         r.version,
				UptimeSeconds:   int64(uptime.Seconds()),
				StoredEnvelopes: r.store.Count(),
			},
		},
	}
}

// SetDraining toggles the relay's drain mode.
func (r *Relay) SetDraining(v bool) { r.draining.Store(v) }

// Draining reports whether the relay is in drain mode.
func (r *Relay) Draining() bool { return r.draining.Load() }

// --- Client methods ---

// storeRespError maps a STORE error response to a sentinel where one exists, so callers
// can errors.Is on it (e.g. ErrMailboxFull → the web send surfaces a distinct status,
// the bridge maps it to a 452 tempfail). Returns nil when the response is not an error.
func storeRespError(resp *dmcnpb.RelayResponse) error {
	errResp := resp.GetError()
	if errResp == nil {
		return nil
	}
	switch errResp.Code {
	case "UNREGISTERED_SENDER":
		return ErrUnregisteredSender
	case "RATE_LIMITED":
		return ErrRateLimited
	case "MAILBOX_FULL":
		return ErrMailboxFull
	default:
		return fmt.Errorf("relay: store: %s: %s", errResp.Code, errResp.Message)
	}
}

// ClientStore sends a STORE request to a remote relay node.
func (r *Relay) ClientStore(ctx context.Context, peerID peer.ID, senderKP *identity.IdentityKeyPair, env *message.EncryptedEnvelope) ([32]byte, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: open stream: %w", err)
	}
	defer s.Close()

	// Serialize envelope for hashing
	envProto := env.ToProto()
	envBytes, err := proto.Marshal(envProto)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: marshal envelope: %w", err)
	}
	envHash := crypto.SHA256Hash(envBytes)

	// Sign envelope hash
	sig, err := crypto.Sign(senderKP.Ed25519Private, envHash[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: sign: %w", err)
	}

	req := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_Store{
			Store: &dmcnpb.StoreRequest{
				SenderAddress:   "", // filled by caller context
				SenderSignature: sig,
				Envelope:        envProto,
			},
		},
	}

	if err := writeRequest(s, req); err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: write: %w", err)
	}

	resp, err := readResponse(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: read response: %w", err)
	}

	if err := storeRespError(resp); err != nil {
		return [32]byte{}, err
	}

	storeResp := resp.GetStore()
	if storeResp == nil {
		return [32]byte{}, errors.New("relay: store: unexpected response type")
	}

	copy(envHash[:], storeResp.EnvelopeHash)
	return envHash, nil
}

// ClientStoreWithAddress sends a STORE request with explicit sender address.
func (r *Relay) ClientStoreWithAddress(ctx context.Context, peerID peer.ID, senderAddr string, senderKP *identity.IdentityKeyPair, env *message.EncryptedEnvelope) ([32]byte, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: open stream: %w", err)
	}
	defer s.Close()

	envProto := env.ToProto()
	envBytes, err := proto.Marshal(envProto)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: marshal envelope: %w", err)
	}
	envHash := crypto.SHA256Hash(envBytes)

	sig, err := crypto.Sign(senderKP.Ed25519Private, envHash[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: sign: %w", err)
	}

	req := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_Store{
			Store: &dmcnpb.StoreRequest{
				SenderAddress:   senderAddr,
				SenderSignature: sig,
				Envelope:        envProto,
			},
		},
	}

	if err := writeRequest(s, req); err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: write: %w", err)
	}

	resp, err := readResponse(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: read response: %w", err)
	}

	if err := storeRespError(resp); err != nil {
		return [32]byte{}, err
	}

	storeResp := resp.GetStore()
	if storeResp == nil {
		return [32]byte{}, errors.New("relay: store: unexpected response type")
	}

	copy(envHash[:], storeResp.EnvelopeHash)
	return envHash, nil
}

// ClientFetch authenticates to a remote relay and retrieves pending envelopes.
func (r *Relay) ClientFetch(ctx context.Context, peerID peer.ID, kp *identity.IdentityKeyPair, address string) ([]*message.EncryptedEnvelope, [][32]byte, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: open stream: %w", err)
	}
	defer s.Close()

	// 1. Send FetchInit
	req := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_FetchInit{
			FetchInit: &dmcnpb.FetchInit{Address: address},
		},
	}
	if err := writeRequest(s, req); err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: write init: %w", err)
	}

	// 2. Read challenge
	resp, err := readResponse(s)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: read challenge: %w", err)
	}
	if errResp := resp.GetError(); errResp != nil {
		return nil, nil, fmt.Errorf("relay: fetch: %s: %s", errResp.Code, errResp.Message)
	}
	challenge := resp.GetFetchChallenge()
	if challenge == nil {
		return nil, nil, errors.New("relay: fetch: expected challenge response")
	}

	// 3. Sign nonce and send proof
	sig, err := crypto.Sign(kp.Ed25519Private, challenge.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: sign challenge: %w", err)
	}

	proofReq := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_FetchProof{
			FetchProof: &dmcnpb.FetchProof{
				Address:   address,
				Nonce:     challenge.Nonce,
				Signature: sig,
			},
		},
	}
	if err := writeRequest(s, proofReq); err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: write proof: %w", err)
	}

	// 4. Read envelopes
	resp, err = readResponse(s)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: read envelopes: %w", err)
	}
	if errResp := resp.GetError(); errResp != nil {
		if errResp.Code == "AUTH_FAILED" {
			return nil, nil, ErrAuthFailed
		}
		return nil, nil, fmt.Errorf("relay: fetch: %s: %s", errResp.Code, errResp.Message)
	}

	fetchResp := resp.GetFetch()
	if fetchResp == nil {
		return nil, nil, errors.New("relay: fetch: unexpected response type")
	}

	envs := make([]*message.EncryptedEnvelope, len(fetchResp.Envelopes))
	hashes := make([][32]byte, len(fetchResp.EnvelopeHashes))
	for i, pb := range fetchResp.Envelopes {
		env, err := message.EncryptedEnvelopeFromProto(pb)
		if err != nil {
			return nil, nil, fmt.Errorf("relay: fetch: envelope %d: %w", i, err)
		}
		envs[i] = env
		if i < len(fetchResp.EnvelopeHashes) {
			copy(hashes[i][:], fetchResp.EnvelopeHashes[i])
		}
	}

	return envs, hashes, nil
}

// ClientStorePreSigned sends a STORE request with a pre-computed signature.
// This is used by the web client where the browser signs the envelope hash
// and the server relays it without having access to private keys.
func (r *Relay) ClientStorePreSigned(ctx context.Context, peerID peer.ID, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: open stream: %w", err)
	}
	defer s.Close()

	envProto := env.ToProto()

	req := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_Store{
			Store: &dmcnpb.StoreRequest{
				SenderAddress:   senderAddr,
				SenderSignature: signature,
				Envelope:        envProto,
			},
		},
	}

	if err := writeRequest(s, req); err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: write: %w", err)
	}

	resp, err := readResponse(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: read response: %w", err)
	}

	if err := storeRespError(resp); err != nil {
		return [32]byte{}, err
	}

	storeResp := resp.GetStore()
	if storeResp == nil {
		return [32]byte{}, errors.New("relay: store: unexpected response type")
	}

	var envHash [32]byte
	copy(envHash[:], storeResp.EnvelopeHash)
	return envHash, nil
}

// ClientFetchChallenge sends a FetchInit and returns the challenge nonce and
// the open stream. The caller must complete the exchange by calling
// ClientFetchComplete with the signed nonce.
func (r *Relay) ClientFetchChallenge(ctx context.Context, peerID peer.ID, address string) ([]byte, network.Stream, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: open stream: %w", err)
	}

	// Send FetchInit
	req := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_FetchInit{
			FetchInit: &dmcnpb.FetchInit{Address: address},
		},
	}
	if err := writeRequest(s, req); err != nil {
		s.Close()
		return nil, nil, fmt.Errorf("relay: fetch: write init: %w", err)
	}

	// Read challenge
	resp, err := readResponse(s)
	if err != nil {
		s.Close()
		return nil, nil, fmt.Errorf("relay: fetch: read challenge: %w", err)
	}
	if errResp := resp.GetError(); errResp != nil {
		s.Close()
		switch errResp.Code {
		case "ACCESS_SUSPENDED":
			return nil, nil, ErrAccessSuspended
		case "ACCESS_CLOSED":
			return nil, nil, ErrAccessClosed
		default:
			return nil, nil, fmt.Errorf("relay: fetch: %s: %s", errResp.Code, errResp.Message)
		}
	}
	challenge := resp.GetFetchChallenge()
	if challenge == nil {
		s.Close()
		return nil, nil, errors.New("relay: fetch: expected challenge response")
	}

	return challenge.Nonce, s, nil
}

// ClientFetchComplete sends the signed proof on an open stream (from
// ClientFetchChallenge) and returns the envelopes. The stream is closed
// when this method returns.
func (r *Relay) ClientFetchComplete(s network.Stream, address string, nonce, signature []byte) ([]*message.EncryptedEnvelope, [][32]byte, error) {
	defer s.Close()

	proofReq := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_FetchProof{
			FetchProof: &dmcnpb.FetchProof{
				Address:   address,
				Nonce:     nonce,
				Signature: signature,
			},
		},
	}
	if err := writeRequest(s, proofReq); err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: write proof: %w", err)
	}

	resp, err := readResponse(s)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: fetch: read envelopes: %w", err)
	}
	if errResp := resp.GetError(); errResp != nil {
		if errResp.Code == "AUTH_FAILED" {
			return nil, nil, ErrAuthFailed
		}
		return nil, nil, fmt.Errorf("relay: fetch: %s: %s", errResp.Code, errResp.Message)
	}

	fetchResp := resp.GetFetch()
	if fetchResp == nil {
		return nil, nil, errors.New("relay: fetch: unexpected response type")
	}

	envs := make([]*message.EncryptedEnvelope, len(fetchResp.Envelopes))
	hashes := make([][32]byte, len(fetchResp.EnvelopeHashes))
	for i, pb := range fetchResp.Envelopes {
		env, err := message.EncryptedEnvelopeFromProto(pb)
		if err != nil {
			return nil, nil, fmt.Errorf("relay: fetch: envelope %d: %w", i, err)
		}
		envs[i] = env
		if i < len(fetchResp.EnvelopeHashes) {
			copy(hashes[i][:], fetchResp.EnvelopeHashes[i])
		}
	}

	return envs, hashes, nil
}

// clientMailboxSend performs the FETCH challenge handshake, signs the nonce, and
// sends the mailbox op, returning the open stream for the caller to read the
// response(s). The caller must Close the stream.
func (r *Relay) clientMailboxSend(ctx context.Context, peerID peer.ID, kp *identity.IdentityKeyPair, address string, op *dmcnpb.MailboxOp) (network.Stream, error) {
	nonce, s, err := r.ClientFetchChallenge(ctx, peerID, address)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.Sign(kp.Ed25519Private, nonce)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("relay: mailbox: sign challenge: %w", err)
	}
	op.Nonce = nonce
	op.Signature = sig
	if err := writeRequest(s, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_MailboxOp{MailboxOp: op},
	}); err != nil {
		s.Close()
		return nil, fmt.Errorf("relay: mailbox: write op: %w", err)
	}
	return s, nil
}

// mailboxRespError maps an error response to a sentinel where one exists.
func mailboxRespError(resp *dmcnpb.RelayResponse) error {
	errResp := resp.GetError()
	if errResp == nil {
		return nil
	}
	switch errResp.Code {
	case "AUTH_FAILED":
		return ErrAuthFailed
	case "NOT_FOUND":
		return ErrEnvelopeNotFound
	case "CONFLICT":
		return ErrKvConflict
	case "QUOTA_EXCEEDED":
		return ErrQuotaExceeded
	default:
		return fmt.Errorf("relay: mailbox: %s: %s", errResp.Code, errResp.Message)
	}
}

// clientMailboxUnary sends an op and reads a single response frame (LIST, DELETE).
func (r *Relay) clientMailboxUnary(ctx context.Context, peerID peer.ID, kp *identity.IdentityKeyPair, address string, op *dmcnpb.MailboxOp) (*dmcnpb.RelayResponse, error) {
	s, err := r.clientMailboxSend(ctx, peerID, kp, address, op)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	resp, err := readResponse(s)
	if err != nil {
		return nil, fmt.Errorf("relay: mailbox: read response: %w", err)
	}
	if err := mailboxRespError(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ClientMailboxList fetches one page of header previews from a recipient's
// mailbox. Pass an empty cursor for the first page; the returned nextCursor is
// empty once the mailbox has been fully drained. Listing is non-consuming.
func (r *Relay) ClientMailboxList(ctx context.Context, peerID peer.ID, kp *identity.IdentityKeyPair, address string, limit int, cursor []byte) ([]*dmcnpb.MailboxEntry, []byte, error) {
	resp, err := r.clientMailboxUnary(ctx, peerID, kp, address, &dmcnpb.MailboxOp{
		Op: &dmcnpb.MailboxOp_List{List: &dmcnpb.MailboxListOp{Limit: uint32(limit), Cursor: cursor}},
	})
	if err != nil {
		return nil, nil, err
	}
	list := resp.GetMailboxList()
	if list == nil {
		return nil, nil, errors.New("relay: mailbox list: unexpected response type")
	}
	return list.Entries, list.NextCursor, nil
}

// ClientMailboxBody fetches the body of one message from a recipient's mailbox.
// The body is streamed in chunks (so it may exceed the per-frame cap) and
// reassembled. Returns ErrEnvelopeNotFound if the message is not present.
func (r *Relay) ClientMailboxBody(ctx context.Context, peerID peer.ID, kp *identity.IdentityKeyPair, address string, hash [32]byte) (*dmcnpb.MailboxBody, error) {
	s, err := r.clientMailboxSend(ctx, peerID, kp, address, &dmcnpb.MailboxOp{
		Op: &dmcnpb.MailboxOp_Body{Body: &dmcnpb.MailboxBodyOp{Hash: hash[:]}},
	})
	if err != nil {
		return nil, err
	}
	defer s.Close()

	resp, err := readResponse(s)
	if err != nil {
		return nil, fmt.Errorf("relay: mailbox body: read header: %w", err)
	}
	if err := mailboxRespError(resp); err != nil {
		return nil, err
	}
	hdr := resp.GetMailboxBodyHeader()
	if hdr == nil {
		return nil, errors.New("relay: mailbox body: unexpected response type")
	}
	bodyBytes, err := readChunked(s, hdr.BodyTotalSize)
	if err != nil {
		return nil, fmt.Errorf("relay: mailbox body: read chunks: %w", err)
	}
	return &dmcnpb.MailboxBody{
		EncryptedBody: bodyBytes,
		BodyNonce:     hdr.BodyNonce,
		BodyTag:       hdr.BodyTag,
		BodySizeClass: hdr.BodySizeClass,
	}, nil
}

// ClientMailboxDelete removes one message from a recipient's mailbox. Deleting a
// message that is not present is not an error (idempotent).
func (r *Relay) ClientMailboxDelete(ctx context.Context, peerID peer.ID, kp *identity.IdentityKeyPair, address string, hash [32]byte) error {
	resp, err := r.clientMailboxUnary(ctx, peerID, kp, address, &dmcnpb.MailboxOp{
		Op: &dmcnpb.MailboxOp_Delete{Delete: &dmcnpb.MailboxDeleteOp{Hash: hash[:]}},
	})
	if err != nil {
		return err
	}
	if del := resp.GetMailboxDelete(); del == nil || !del.Success {
		return errors.New("relay: mailbox delete: unexpected response type")
	}
	return nil
}

// --- Pre-signed mailbox ops (for proxies that do not hold the private key) ---
//
// These complete a mailbox op on a stream already challenged via
// ClientFetchChallenge, using a signature produced elsewhere (e.g. in a browser).
// They mirror ClientFetchComplete and close the stream on return.

func sendMailboxOpProof(s network.Stream, nonce, signature []byte, op *dmcnpb.MailboxOp) error {
	op.Nonce = nonce
	op.Signature = signature
	return writeRequest(s, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_MailboxOp{MailboxOp: op},
	})
}

// ClientMailboxListComplete sends a LIST op with an externally-produced signature
// over the challenge nonce and returns the page of header previews.
func (r *Relay) ClientMailboxListComplete(s network.Stream, nonce, signature []byte, limit int, cursor []byte) ([]*dmcnpb.MailboxEntry, []byte, error) {
	defer s.Close()
	if err := sendMailboxOpProof(s, nonce, signature, &dmcnpb.MailboxOp{
		Op: &dmcnpb.MailboxOp_List{List: &dmcnpb.MailboxListOp{Limit: uint32(limit), Cursor: cursor}},
	}); err != nil {
		return nil, nil, fmt.Errorf("relay: mailbox list: write op: %w", err)
	}
	resp, err := readResponse(s)
	if err != nil {
		return nil, nil, fmt.Errorf("relay: mailbox list: read response: %w", err)
	}
	if err := mailboxRespError(resp); err != nil {
		return nil, nil, err
	}
	list := resp.GetMailboxList()
	if list == nil {
		return nil, nil, errors.New("relay: mailbox list: unexpected response type")
	}
	return list.Entries, list.NextCursor, nil
}

// ClientMailboxBodyComplete sends a BODY op with an externally-produced signature
// and reassembles the chunked body.
func (r *Relay) ClientMailboxBodyComplete(s network.Stream, nonce, signature []byte, hash [32]byte) (*dmcnpb.MailboxBody, error) {
	defer s.Close()
	if err := sendMailboxOpProof(s, nonce, signature, &dmcnpb.MailboxOp{
		Op: &dmcnpb.MailboxOp_Body{Body: &dmcnpb.MailboxBodyOp{Hash: hash[:]}},
	}); err != nil {
		return nil, fmt.Errorf("relay: mailbox body: write op: %w", err)
	}
	resp, err := readResponse(s)
	if err != nil {
		return nil, fmt.Errorf("relay: mailbox body: read header: %w", err)
	}
	if err := mailboxRespError(resp); err != nil {
		return nil, err
	}
	hdr := resp.GetMailboxBodyHeader()
	if hdr == nil {
		return nil, errors.New("relay: mailbox body: unexpected response type")
	}
	bodyBytes, err := readChunked(s, hdr.BodyTotalSize)
	if err != nil {
		return nil, fmt.Errorf("relay: mailbox body: read chunks: %w", err)
	}
	return &dmcnpb.MailboxBody{
		EncryptedBody: bodyBytes,
		BodyNonce:     hdr.BodyNonce,
		BodyTag:       hdr.BodyTag,
		BodySizeClass: hdr.BodySizeClass,
	}, nil
}

// ClientMailboxDeleteComplete sends a DELETE op with an externally-produced signature.
func (r *Relay) ClientMailboxDeleteComplete(s network.Stream, nonce, signature []byte, hash [32]byte) error {
	defer s.Close()
	if err := sendMailboxOpProof(s, nonce, signature, &dmcnpb.MailboxOp{
		Op: &dmcnpb.MailboxOp_Delete{Delete: &dmcnpb.MailboxDeleteOp{Hash: hash[:]}},
	}); err != nil {
		return fmt.Errorf("relay: mailbox delete: write op: %w", err)
	}
	resp, err := readResponse(s)
	if err != nil {
		return fmt.Errorf("relay: mailbox delete: read response: %w", err)
	}
	if err := mailboxRespError(resp); err != nil {
		return err
	}
	if del := resp.GetMailboxDelete(); del == nil || !del.Success {
		return errors.New("relay: mailbox delete: unexpected response type")
	}
	return nil
}

// ClientStoreDurable stores a split envelope on a remote mailbox using chunked
// transfer, so the message body may exceed the per-frame cap. The sender signs
// the canonical envelope hash for spam control, exactly like the single-frame STORE.
func (r *Relay) ClientStoreDurable(ctx context.Context, peerID peer.ID, senderAddr string, senderKP *identity.IdentityKeyPair, env *message.EncryptedEnvelope) ([32]byte, error) {
	if !env.IsSplit() {
		return [32]byte{}, errors.New("relay: store durable: requires a split (header/body) envelope")
	}
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: open stream: %w", err)
	}
	defer s.Close()

	envBytes, err := proto.Marshal(env.ToProto())
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: marshal envelope: %w", err)
	}
	envHash := crypto.SHA256Hash(envBytes)
	sig, err := crypto.Sign(senderKP.Ed25519Private, envHash[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: sign: %w", err)
	}

	init := &dmcnpb.StoreInit{
		SenderAddress:      senderAddr,
		SenderSignature:    sig,
		Version:            env.Version,
		MessageId:          env.MessageID[:],
		CreatedAt:          env.CreatedAt,
		Recipients:         recipientsToProto(env.Recipients),
		EncryptedHeader:    env.EncryptedHeader,
		HeaderNonce:        env.HeaderNonce[:],
		HeaderTag:          env.HeaderTag[:],
		HeaderSizeClass:    env.HeaderSizeClass,
		BodyNonce:          env.BodyNonce[:],
		BodyTag:            env.BodyTag[:],
		BodySizeClass:      env.BodySizeClass,
		BodyTotalSize:      uint64(len(env.EncryptedBody)),
		BodyContentAddress: env.BodyContentAddress, // so the reassembled envelope hash matches the signature above
	}
	if err := writeRequest(s, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_StoreInit{StoreInit: init},
	}); err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: write init: %w", err)
	}
	if err := writeChunked(s, env.EncryptedBody); err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: write body chunks: %w", err)
	}

	resp, err := readResponse(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("relay: store: read response: %w", err)
	}
	if err := storeRespError(resp); err != nil {
		return [32]byte{}, err
	}
	storeResp := resp.GetStore()
	if storeResp == nil {
		return [32]byte{}, errors.New("relay: store: unexpected response type")
	}
	var got [32]byte
	copy(got[:], storeResp.EnvelopeHash)
	return got, nil
}

// ClientAck sends an ACK for a delivered envelope.
func (r *Relay) ClientAck(ctx context.Context, peerID peer.ID, envelopeHash [32]byte) error {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return fmt.Errorf("relay: ack: open stream: %w", err)
	}
	defer s.Close()

	req := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_Ack{
			Ack: &dmcnpb.AckRequest{
				EnvelopeHash: envelopeHash[:],
			},
		},
	}
	if err := writeRequest(s, req); err != nil {
		return fmt.Errorf("relay: ack: write: %w", err)
	}

	resp, err := readResponse(s)
	if err != nil {
		return fmt.Errorf("relay: ack: read: %w", err)
	}
	if errResp := resp.GetError(); errResp != nil {
		return fmt.Errorf("relay: ack: %s: %s", errResp.Code, errResp.Message)
	}

	return nil
}

// ClientPing sends a PING to a remote relay.
func (r *Relay) ClientPing(ctx context.Context, peerID peer.ID) (*dmcnpb.PingResponse, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return nil, fmt.Errorf("relay: ping: open stream: %w", err)
	}
	defer s.Close()

	req := &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_Ping{
			Ping: &dmcnpb.PingRequest{},
		},
	}
	if err := writeRequest(s, req); err != nil {
		return nil, fmt.Errorf("relay: ping: write: %w", err)
	}

	resp, err := readResponse(s)
	if err != nil {
		return nil, fmt.Errorf("relay: ping: read: %w", err)
	}
	if errResp := resp.GetError(); errResp != nil {
		return nil, fmt.Errorf("relay: ping: %s: %s", errResp.Code, errResp.Message)
	}

	return resp.GetPing(), nil
}

// clientUnary sends a one-frame request and returns the response (shared by the small
// operator ops). The caller must be admitted with the appropriate credential.
func (r *Relay) clientUnary(ctx context.Context, peerID peer.ID, req *dmcnpb.RelayRequest, what string) (*dmcnpb.RelayResponse, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return nil, fmt.Errorf("relay: %s: open stream: %w", what, err)
	}
	defer s.Close()
	if err := writeRequest(s, req); err != nil {
		return nil, fmt.Errorf("relay: %s: write: %w", what, err)
	}
	resp, err := readResponse(s)
	if err != nil {
		return nil, fmt.Errorf("relay: %s: read: %w", what, err)
	}
	if e := resp.GetError(); e != nil {
		return nil, fmt.Errorf("relay: %s: %s: %s", what, e.Code, e.Message)
	}
	return resp, nil
}

// --- Peer discovery protocol ---

// peersResponse is the JSON response for the peer discovery protocol.
type peersResponse struct {
	Peers []string `json:"peers"`
}

// handlePeers responds to cluster peer discovery requests with the configured
// peers list.
func (r *Relay) handlePeers(s network.Stream) {
	defer s.Close()

	if !r.peerAllowed(s.Conn().RemotePeer()) {
		return // don't reveal the cluster list to non-federated peers
	}

	resp := peersResponse{Peers: r.peers}
	if resp.Peers == nil {
		resp.Peers = []string{}
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	s.Write(lenBuf[:])
	s.Write(data)
}

// ClientPeers queries a remote peer for its cluster peers.
func (r *Relay) ClientPeers(ctx context.Context, peerID peer.ID) ([]string, error) {
	s, err := r.host.NewStream(ctx, peerID, PeersProtocolID)
	if err != nil {
		return nil, fmt.Errorf("relay: peers: open stream: %w", err)
	}
	defer s.Close()

	// Read length-prefixed JSON response.
	var lenBuf [4]byte
	if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("relay: peers: read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > maxMessageSize {
		return nil, errors.New("relay: peers: response too large")
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(s, data); err != nil {
		return nil, fmt.Errorf("relay: peers: read data: %w", err)
	}

	var resp peersResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("relay: peers: unmarshal: %w", err)
	}

	return resp.Peers, nil
}

// Peers returns the configured cluster peers.
func (r *Relay) Peers() []string {
	return r.peers
}

// --- Wire protocol helpers ---
// Messages are length-prefixed: [4-byte big-endian length][protobuf data]

func writeRequest(w io.Writer, req *dmcnpb.RelayRequest) error {
	return writeMessage(w, req)
}

func writeResponse(w io.Writer, resp *dmcnpb.RelayResponse) error {
	return writeMessage(w, resp)
}

func readRequest(r io.Reader) (*dmcnpb.RelayRequest, error) {
	req := &dmcnpb.RelayRequest{}
	if err := readMessage(r, req); err != nil {
		return nil, err
	}
	return req, nil
}

func readResponse(r io.Reader) (*dmcnpb.RelayResponse, error) {
	resp := &dmcnpb.RelayResponse{}
	if err := readMessage(r, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func writeMessage(w io.Writer, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if len(data) > maxMessageSize {
		return errors.New("message too large")
	}

	// Write 4-byte big-endian length prefix
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	return nil
}

func readMessage(r io.Reader, msg proto.Message) error {
	// Read 4-byte big-endian length prefix
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > maxMessageSize {
		return errors.New("message too large")
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read data: %w", err)
	}
	if err := proto.Unmarshal(data, msg); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

// writeFrame writes a single raw length-prefixed frame.
func writeFrame(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write chunk length: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write chunk data: %w", err)
	}
	return nil
}

// readFrame reads a single raw length-prefixed frame (bounded by the per-frame cap).
func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read chunk length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxMessageSize {
		return nil, errors.New("chunk frame too large")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read chunk data: %w", err)
	}
	return data, nil
}

// writeChunked streams data as a sequence of length-prefixed frames, each at most
// bodyChunkSize, so a payload larger than the per-frame cap can cross the wire.
func writeChunked(w io.Writer, data []byte) error {
	for off := 0; off < len(data); off += bodyChunkSize {
		end := off + bodyChunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := writeFrame(w, data[off:end]); err != nil {
			return err
		}
	}
	return nil
}

// readChunked reads length-prefixed frames until exactly total bytes have been
// accumulated, bounded by maxBodySize.
func readChunked(r io.Reader, total uint64) ([]byte, error) {
	if total > maxBodySize {
		return nil, fmt.Errorf("body too large: %d > %d", total, maxBodySize)
	}
	buf := make([]byte, 0, total)
	for uint64(len(buf)) < total {
		frame, err := readFrame(r)
		if err != nil {
			return nil, err
		}
		if uint64(len(buf))+uint64(len(frame)) > total {
			return nil, errors.New("chunk overflow past declared size")
		}
		buf = append(buf, frame...)
	}
	return buf, nil
}

func errorResponse(code, msg string) *dmcnpb.RelayResponse {
	return &dmcnpb.RelayResponse{
		Response: &dmcnpb.RelayResponse_Error{
			Error: &dmcnpb.ErrorResponse{
				Code:    code,
				Message: msg,
			},
		},
	}
}
