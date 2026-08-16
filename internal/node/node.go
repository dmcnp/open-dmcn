// Package node provides a combined DMCN node that runs a DHT registry and
// relay service in a single process. This is the PoC development node
// described in PRD Section 5.3.
package node

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	leveldbds "github.com/ipfs/go-ds-leveldb"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/mertenvg/logr/v2"
	"github.com/multiformats/go-multiaddr"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/keystore"
	"dmcn.dev/open-dmcn/internal/peerpolicy"
	"dmcn.dev/open-dmcn/internal/registry"
	"dmcn.dev/open-dmcn/internal/relay"
)

// Config holds configuration for a DMCN node.
type Config struct {
	ListenAddr           string   // multiaddr string, e.g. "/ip4/0.0.0.0/tcp/7400"
	Peers                []string // multiaddr strings of infra peers: DHT entry points + cluster discovery seeds
	KeystorePath         string   // path to encrypted keystore file
	Passphrase           string   // passphrase for keystore encryption
	IdentityKeyPath      string   // optional path to a persistent libp2p identity key (created if missing); empty means an ephemeral identity
	DataDir              string   // optional dir for persistent stores (registry/mailbox/transit); empty = in-memory
	Mailbox              bool     // opt into the durable mailbox role (requires DataDir); persists messages hold-until-deleted
	MailboxCapacityBytes uint64   // optional mailbox capacity in bytes (0 = unbounded), reported via STAT for load-aware placement
	StorageQuotaBytes    uint64   // optional per-account TOTAL storage quota in bytes — mail + personal-KV (0 = unbounded); node default, raised per account by a RoleQuota grant
	ClientOnly           bool     // run as a pure client: DHT client mode + no relay server handlers (web backend, CLI commands)
	DisableOnionRelay    bool     // opt out of forwarding onion traffic for others (--no-onion-relay); relays forward by default
	// OnionForwardJitter, when > 0, adds a random per-hop delay in [0, jitter)
	// before forwarding/delivering onion packets (timing-correlation hardening).
	OnionForwardJitter time.Duration

	// AllowedPeers gates which libp2p peers may federate (connect, enter the DHT
	// routing table, use peer discovery, open relay streams). Entries are bare
	// base58 peer IDs or full multiaddrs. The allow-set also includes the
	// configured Peers (auto-trusted). Empty ⇒ deny-by-default (AllowNone). A
	// single "*" entry opts into open mode (AllowAll). In Credential-PKI mode this
	// static allow-set is only an escape hatch; trust comes from presented credentials.
	AllowedPeers []string

	// DNSVerifier overrides the DAR DNS-anchoring verifier (defaults to a real DNS
	// lookup). Primarily for tests that exercise countersigned/managed identities
	// without live DNS.
	DNSVerifier registry.DNSVerifier

	// StaticDNS supplies _dmcn records (domain → {fingerprint, fleet, seeds}) that the resolver
	// consults BEFORE real DNS. It provides the trust anchor + discovery seeds in environments
	// with no live DNS (the dev cluster, CI) and doubles as an operator seed-pin / resilience
	// override in production. Keys are matched case-insensitively.
	StaticDNS map[string]domainverify.Record

	// Domain is the DMCN domain this node serves. In credential mode it is taken from the
	// node's credential; it is also used as the provisioning pin for an inert node. The
	// node announces itself as a relay provider under this domain for discovery.
	Domain string

	// BlockedDomains is an optional route-selection block-list: relays whose credential
	// names one of these domains are excluded from onion routing.
	BlockedDomains []string

	// Credential + CredentialDAR enable Credential-PKI mode: the node presents this
	// credential (anchored by this DAR) at the /dmcn/join handshake and gates federation
	// by credentials presented by peers, rather than a static peer-ID allowlist. Both must
	// be set together. A node with neither boots inert (provision-listener only) until one
	// is pushed (S2 provisioning).
	Credential    *identity.Credential
	CredentialDAR *identity.DomainAuthorityRecord

	// Credentials lets a node present SEVERAL {credential, DAR} bundles at /dmcn/join — one
	// per domain it is enrolled in (hosted multi-tenant; e.g. the web, credentialed in each
	// customer DAR with the same key). The first is the primary (relay descriptor + same-domain
	// verify); all are presented so a relay authorizes the peer per target domain. When empty,
	// the singular Credential/CredentialDAR (if set) is the one and only bundle.
	Credentials []CredentialBundle
}

// NOTE (open-dmcn reference implementation): the fleet-ownership surfaces —
// OperatorPubKey/PermitsDir (operator permits) and ProvisionDomain (the /dmcn/provision
// inert-boot) — are omitted. A reference node is authoritative for its own single domain.

// Node is a combined DMCN development node running DHT registry and relay.
type Node struct {
	host             host.Host
	registry         *registry.Registry
	relay            *relay.Relay
	records          *relay.RecordStore             // local authoritative record store (mailbox/serving nodes); nil for pure clients
	staticDNS        map[string]domainverify.Record // static _dmcn records (dev/CI + operator seed-pin), consulted before real DNS
	keystore         *keystore.Keystore
	datastore        *leveldbds.Datastore // persistent store; nil when in-memory
	relayX25519Priv  [32]byte             // onion-routing key (relays only); zero for client-only
	relayX25519Pub   [32]byte
	peers            []string // infra peers: DHT entry points + cluster discovery seeds
	clientOnly       bool
	dataDir          string                           // persistent dir (for credential persistence); empty = ephemeral
	domain           string                           // DMCN domain this node serves (from its credential); used for relay provider announce
	blockedDomains   map[string]bool                  // lowercased domains excluded from route selection
	mailFilterStore  *relay.PersistentMailFilterStore // recipient block/allow lists (mailbox nodes only)
	mailboxFilterPub [32]byte                         // relay's mailbox X25519 key clients seal filter lists to
	credential       *identity.Credential             // this node's PRIMARY membership credential (Credential PKI); nil outside cred mode
	credentialDAR    *identity.DomainAuthorityRecord  // the DAR anchoring our primary credential (bundled at /dmcn/join)
	joinBundles      []CredentialBundle               // ALL of this node's {credential, DAR} bundles, presented at /dmcn/join (one per domain)
	credentials      *credentialSet                   // peers that presented a valid credential (gates participation)
	credMu           sync.Mutex                       // guards credential/credentialDAR + meshUp on the provisioning transition
	meshUp           bool                             // startMesh has run (idempotent guard)
	joinOnce         sync.Once                        // /dmcn/join handler+notifiee registration (idempotent; the kick loop still re-runs)
	policy           peerpolicy.Policy                // federation gate; consulted for discovered peers
	operatorPub      ed25519.PublicKey                // fleet root (config-anchored); verifies operator-signed fleet credentials at /dmcn/join
	log              logr.Logger
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup // background loops (maintainPeers, republish)
}

// New creates and starts a new DMCN node.
func New(ctx context.Context, cfg Config, log ...logr.Logger) (*Node, error) {
	var l logr.Logger
	if len(log) > 0 {
		l = log[0]
	} else {
		l = logr.With(logr.M("component", "node"))
	}

	ctx, cancel := context.WithCancel(ctx)

	listenAddr, err := multiaddr.NewMultiaddr(cfg.ListenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("node: invalid listen address: %w", err)
	}

	// Build the federation policy before the host: it depends only on parsed
	// config, and the host needs the ConnectionGater at construction time.
	policy, err := buildPeerPolicy(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("node: peer policy: %w", err)
	}
	// Credential mode (Credential PKI): when the node holds a Credential + the DAR that
	// anchors it, federation is gated by credentials presented at /dmcn/join rather than
	// a static peer-ID allowlist. Connections stay OPEN (so the join/provision handshakes
	// can run); PARTICIPATION — DHT routing-table admission, org discovery, relay streams —
	// is gated by the in-memory credentialSet. This is reentrancy-free (in-memory check).
	// Normalize the credential set: a node may hold several {credential, DAR} bundles (one per
	// domain it is enrolled in). The first is the primary (relay descriptor + same-domain
	// verify); all are presented at /dmcn/join. A singular Credential is just a one-bundle set.
	joinBundles := cfg.Credentials
	if len(joinBundles) == 0 && cfg.Credential != nil {
		joinBundles = []CredentialBundle{{Credential: cfg.Credential, DAR: cfg.CredentialDAR}}
	}
	if cfg.Credential == nil && len(joinBundles) > 0 {
		cfg.Credential, cfg.CredentialDAR = joinBundles[0].Credential, joinBundles[0].DAR
	}

	// A node holds its own credential when it has one to PRESENT outbound — a domain credential
	// (DAR-anchored) or a fleet credential (chains to the config operator root, no DAR). Holding
	// one is NOT required to VALIDATE inbound credentials: every non-inert node runs /dmcn/join
	// and gates participation by credentialPolicy, so a credential-less node is a pure relay.
	hasCred := cfg.Credential != nil
	credentials := newCredentialSet()
	// Participation (DHT routing-table admission, relay + discovery streams) is ALWAYS
	// credential-gated: admit a peer in the static allow-set (dev `*` / explicit bootstrap) OR
	// one that presented a valid credential at /dmcn/join. Connections stay open so the join /
	// provision handshakes can run; there is no hard connection gater.
	partPolicy := &credentialPolicy{static: policy, set: credentials}
	l.Infof("federation: credential-gated (static=%s)", policy.Name())

	opts := []libp2p.Option{
		libp2p.ListenAddrs(listenAddr),
		// Disable TCP reuseport. By default libp2p dials out from its listen port
		// (e.g. 7400); some VPS networks silently drop those packets (the SYN-ACK
		// never returns → i/o timeout) while ephemeral-source dials succeed, which
		// fragments the cluster. DMCN only uses TCP, so dialing from ephemeral
		// ports is the right trade-off. (Equivalent to LIBP2P_TCP_REUSEPORT=false.)
		libp2p.Transport(tcp.NewTCPTransport, tcp.DisableReuseport()),
	}
	// No hard connection gater: connections stay open so /dmcn/join and /dmcn/provision can
	// run; participation is credential-gated by partPolicy (credentialPolicy) downstream.
	if cfg.IdentityKeyPath != "" {
		priv, err := LoadOrCreateIdentityKey(cfg.IdentityKeyPath)
		if err != nil {
			cancel()
			return nil, err
		}
		opts = append(opts, libp2p.Identity(priv))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("node: create libp2p host: %w", err)
	}

	// Open the persistent store (shared by registry now; mailbox/transit later).
	var store *leveldbds.Datastore
	if cfg.DataDir != "" {
		// Pre-create the data + store dirs service-user-only (0700). leveldb would otherwise
		// create them world-readable (0755), exposing mailbox ciphertext and the sealed
		// account store on a shared host. Pre-creating makes leveldb's internal MkdirAll a
		// no-op so the 0700 mode sticks; Chmod also tightens a dir left over from an older run.
		storeDir := filepath.Join(cfg.DataDir, "store")
		if err = os.MkdirAll(storeDir, 0o700); err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("node: create datastore dir: %w", err)
		}
		_ = os.Chmod(cfg.DataDir, 0o700)
		_ = os.Chmod(storeDir, 0o700)
		store, err = leveldbds.NewDatastore(storeDir, nil)
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("node: open datastore: %w", err)
		}
	}

	// A client-only node participates as a DHT *client* (it can register and
	// look up records by routing through server nodes, but does not serve the
	// DHT or relay) — the right footprint for the web backend and the short-lived
	// CLI commands, which are pure clients, not infrastructure.
	if cfg.ClientOnly && cfg.Mailbox {
		h.Close()
		cancel()
		return nil, fmt.Errorf("node: client-only node cannot host a mailbox")
	}
	// Create the (DHT-free) identity verification registry. Records are served through the fleet
	// resolver + local RecordStore, installed as its RecordSource after the node is built.
	var regOpts []registry.Option
	if cfg.DNSVerifier != nil {
		regOpts = append(regOpts, registry.WithDNSVerifier(cfg.DNSVerifier))
	}
	reg := registry.New(regOpts...)

	// Relays carry an onion-routing X25519 key (persisted when DataDir is set);
	// client-only nodes don't forward and don't need one.
	var relayPriv, relayPub [32]byte
	if !cfg.ClientOnly {
		relayPriv, relayPub, err = loadOrCreateRelayX25519Key(cfg.DataDir)
		if err != nil {
			reg.Close()
			h.Close()
			if store != nil {
				store.Close()
			}
			cancel()
			return nil, err
		}
	}

	// NOTE (open-dmcn): fleet operator permits are omitted (single self-hosted domain).

	// Create relay with registry lookup. Opting into the mailbox role requires a
	// persistent datastore (it is the recipient's durable, hold-until-deleted home).
	// recStore is the node's local authoritative record store for the fleet-resolution ops
	// (the DHT replacement). Set for serving (mailbox) nodes below; nil for pure clients.
	var recStore *relay.RecordStore

	relayOpts := []relay.Option{
		relay.WithPeers(cfg.Peers),
		// Enforce per-domain policy (require-countersign) on mailbox reads.
		relay.WithFetchPolicy(reg.AddressUsable),
		// Learn each hosted mailbox's effective onion policy (mailbox OR domain) at FETCH.
		relay.WithOnionPolicy(reg.RequiresOnion),
		// Defense-in-depth: drop relay/org streams from non-federated peers.
		relay.WithPeerPolicy(partPolicy),
		// Fleet role check (operator-rooted credentials) gating the relay→relay handoff inject:
		// the pushing peer must hold the fleet 'node' role.
		relay.WithPeerRoleCheck(func(p peer.ID, role string) bool {
			return credentials.hasFleetRole(p, role)
		}),
		// Fleet grant check (operator-rooted credentials) gating fleet/operator ops:
		// RequestMailbox needs 'routing'; SetDrain/Accounts/MailboxHandoff need 'admin'. These
		// chain to the config operator root, never a domain — so a domain credential's grant can
		// never authorize a fleet op (the confused-deputy guard).
		relay.WithPeerGrantCheck(func(p peer.ID, grant string) bool {
			return credentials.hasFleetGrant(p, grant)
		}),
	}
	// Make the relay's in-flight message store durable when a datastore is
	// available, so queued mail survives a restart.
	if store != nil {
		relayOpts = append(relayOpts, relay.WithMessageDatastore(store))
	}
	// Local authoritative record store for the fleet-resolution ops (the DHT replacement).
	// EVERY serving node runs one — full replication means each fleet node can answer for the
	// domains the fleet hosts, and each serves its OWN signed relay descriptor (onion routing),
	// independent of whether it hosts a mailbox. Persistent when a datastore is available;
	// otherwise in-memory (a pure onion relay needs no disk). Pure clients never serve records.
	if !cfg.ClientOnly {
		var recDS ds.Batching
		if store != nil {
			recDS = store
		} else {
			recDS = dssync.MutexWrap(ds.NewMapDatastore())
		}
		recStore = relay.NewRecordStore(recDS)
		relayOpts = append(relayOpts, relay.WithRecordStore(recStore))
	}
	var mailFilterStore *relay.PersistentMailFilterStore
	var mailboxFilterPriv, mailboxFilterPub [32]byte
	if cfg.Mailbox {
		if store == nil {
			reg.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("node: mailbox role requires DataDir for persistent storage")
		}
		relayOpts = append(relayOpts, relay.WithMailbox(relay.NewMailboxStore(store)))
		if cfg.MailboxCapacityBytes > 0 {
			relayOpts = append(relayOpts, relay.WithMailboxCapacity(cfg.MailboxCapacityBytes))
		}
		// Node-local self-encrypted account list (sealed with a node-held secret), for drain.
		accStore, accErr := relay.NewAccountStore(store, relayPriv[:])
		if accErr != nil {
			reg.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("node: account store: %w", accErr)
		}
		relayOpts = append(relayOpts, relay.WithAccountStore(accStore))

			// NOTE (open-dmcn): the per-account quota and access-assertion stores are
			// omitted. Per-account entitlements (storage grants, suspend/close assertions)
			// are an operator concern outside the core protocol — see SPEC.md §8. A
			// self-hosting operator sets one node-wide cap via WithStorageQuota and is its
			// own authority over the accounts it serves; there is nobody to sell an upgrade to.

		// NOTE (open-dmcn): the per-account OUTBOUND send-counter store is omitted — the ops
		// that fed it (the operate.go ConsumeSendInject + the bridge send-cap) are extension
		// surfaces dropped from the reference implementation; a self-host is its own send authority.

		// Recipient mail filtering: a relay-held mailbox X25519 key opens the
		// dual-sealed filter list so blocked senders are silently dropped at STORE.
		mailboxFilterPriv, mailboxFilterPub, err = loadOrCreateMailboxFilterKey(cfg.DataDir)
		if err != nil {
			reg.Close()
			h.Close()
			store.Close()
			cancel()
			return nil, err
		}
		mailFilterStore = relay.NewMailFilterStore(store)
		// senderVerified powers the allow-list "admit any verified sender" option.
		verified := func(vctx context.Context, rec *identity.IdentityRecord) bool {
			tier, verr := reg.VerifyManagedIdentity(vctx, rec)
			return verr == nil && tier == identity.TierDomainDNS
		}
		relayOpts = append(relayOpts, relay.WithMailboxFilter(mailFilterStore, mailboxFilterPriv, mailboxFilterPub, verified))

		// Owner-only personal storage substrate (Sent, read/unread+labels, contacts,
		// settings), over the same datastore. Sealed to the owner alone — the relay
		// only ever holds ciphertext. Owner auth reuses the FETCH challenge.
		relayOpts = append(relayOpts, relay.WithPersonalKv(relay.NewPersonalKvStore(store)))
		if cfg.StorageQuotaBytes > 0 {
			relayOpts = append(relayOpts, relay.WithStorageQuota(cfg.StorageQuotaBytes))
		}
		// Replicate personal-KV writes across the owner's hints when the owner's domain
		// opts into mailbox replication (same policy that fans out mail STORE).
		relayOpts = append(relayOpts, relay.WithReplicatePolicy(reg.ReplicatesMailbox))
	}
	// Participate in onion forwarding by default (relays only); opt out with
	// DisableOnionRelay (the --no-onion-relay knob).
	if !cfg.ClientOnly && !cfg.DisableOnionRelay {
		relayOpts = append(relayOpts, relay.WithOnionKey(relayPriv))
		if cfg.OnionForwardJitter > 0 {
			relayOpts = append(relayOpts, relay.WithOnionJitter(cfg.OnionForwardJitter))
		}
		// A peer counts as a relay (vs a client doing a 1-hop self-delivery) if it
		// publishes a RelayDescriptor. Cache positives — relays are stable.
		var relayPeers sync.Map // peer.ID -> true
		relayOpts = append(relayOpts, relay.WithOnionPeerCheck(func(p peer.ID) bool {
			if _, ok := relayPeers.Load(p); ok {
				return true
			}
			lctx, lcancel := context.WithTimeout(ctx, 2*time.Second)
			defer lcancel()
			if _, err := reg.LookupRelayDescriptor(lctx, p.String()); err == nil {
				relayPeers.Store(p, true)
				return true
			}
			return false
		}))
	}
	rl := relay.New(h, reg.Lookup, relayOpts...)
	// Client-only nodes use the relay's Client* methods (which open their own
	// streams) but do not register the server-side stream handlers.
	if !cfg.ClientOnly {
		rl.Start()
		// A server node without the durable mailbox role still accepts STOREs, but they
		// land in the transient in-memory store and are lost on restart. The CLI defaults
		// the mailbox role on, so this only fires for a deliberate --no-mailbox node — make
		// the routing-only posture loud rather than a silent data-loss footgun.
		if !cfg.Mailbox {
			l.Warn("durable mailbox role OFF: this node forwards/looks up but does not durably store mail (inbound STORE falls to a transient in-memory store, lost on restart). Enable the mailbox role + a data dir to host mailboxes.")
		}
	}

	// Create keystore
	var ks *keystore.Keystore
	if cfg.KeystorePath != "" {
		ks = keystore.New(cfg.KeystorePath, cfg.Passphrase)
	}

	n := &Node{
		host:             h,
		registry:         reg,
		relay:            rl,
		records:          recStore,
		staticDNS:        lowerDNSMap(cfg.StaticDNS),
		keystore:         ks,
		datastore:        store,
		relayX25519Priv:  relayPriv,
		relayX25519Pub:   relayPub,
		peers:            cfg.Peers,
		clientOnly:       cfg.ClientOnly,
		dataDir:          cfg.DataDir,
		domain:           cfg.Domain,
		blockedDomains:   lowerSet(cfg.BlockedDomains),
		mailFilterStore:  mailFilterStore,
		mailboxFilterPub: mailboxFilterPub,
		policy:           partPolicy,
		credential:       cfg.Credential,
		credentialDAR:    cfg.CredentialDAR,
		joinBundles:      joinBundles,
		credentials:      credentials,
		log:              l,
		ctx:              ctx,
		cancel:           cancel,
	}

	// Install the DHT-free record source: every registry Lookup* (and thus every credential/DAR
	// verification path) reads through the fleet resolver + local RecordStore. This is the ONLY
	// record path now — the DHT is gone.
	n.registry.SetRecordSource(n.recordSource())

	// A node holding its own domain credential announces as a relay provider under it.
	// (open-dmcn omits the /dmcn/provision re-provisioning service.)
	if hasCred && n.credential.Domain != "" {
		n.domain = n.credential.Domain
	}
	// ALWAYS validate inbound credentials (and present our own, if any) at /dmcn/join — a
	// credential-less node is a pure relay that admits inbound credentialed peers.
	n.startJoinService()
	// Serving nodes seed their own domain DARs into the local RecordStore so resolvers can fetch
	// them (the DAR the resolver anchors an identity record against) even before any operator push.
	n.seedOwnRecords(n.ctx)
	n.startMesh()

	return n, nil
}

// startMesh connects the configured peers and starts the maintenance + publish loops. It
// runs at New time for an already-credentialed (or legacy) node, and is deferred until a
// credential is pushed for an inert node (provisioning). Idempotent via meshUp.
func (n *Node) startMesh() {
	n.credMu.Lock()
	if n.meshUp {
		n.credMu.Unlock()
		return
	}
	n.meshUp = true
	n.credMu.Unlock()

	for _, peerAddr := range n.peers {
		if err := n.ConnectPeer(peerAddr); err != nil {
			n.log.Warnf("failed to connect to peer %s: %v", peerAddr, err)
		}
	}
	if len(n.peers) > 0 {
		n.discoverPeers(n.ctx, n.peers)
	}
	if len(n.peers) > 0 {
		n.wg.Add(1)
		go func() { defer n.wg.Done(); n.maintainPeers(n.peers) }()
	}
	// Relays advertise their onion-routing key so senders can encrypt layers to them.
	if !n.clientOnly {
		n.wg.Add(1)
		go func() { defer n.wg.Done(); n.publishRelayDescriptor() }()
	}
}

// peerReconnectInterval is how often maintainPeers re-checks cluster peers.
const peerReconnectInterval = 30 * time.Second

// maintainPeers periodically reconnects to configured cluster peers that are not
// currently connected, so the cluster recovers from a fragmented startup without
// operator intervention.
func (n *Node) maintainPeers(peers []string) {
	seen := make(map[string]bool)
	uniq := peers[:0:0]
	for _, p := range peers {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		uniq = append(uniq, p)
	}
	if len(uniq) == 0 {
		return
	}

	ticker := time.NewTicker(peerReconnectInterval)
	defer ticker.Stop()
	for {
		for _, addr := range uniq {
			info, err := ParseRelayHint(addr)
			if err != nil || info.ID == n.host.ID() {
				continue
			}
			if n.host.Network().Connectedness(info.ID) == network.Connected {
				continue
			}
			if err := n.ConnectPeer(addr); err != nil {
				n.log.Debugf("reconnect to cluster peer %s failed: %v", addr, err)
			} else {
				n.log.Infof("reconnected to cluster peer %s", addr)
			}
		}
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Host returns the underlying libp2p host.
func (n *Node) Host() host.Host {
	return n.host
}

// Registry returns the DHT identity registry.
func (n *Node) Registry() *registry.Registry {
	return n.registry
}

// Relay returns the relay service.
// Records returns the node's local authoritative record store (the fleet-resolution source of
// truth), or nil for a pure client. Registration/assignment paths populate it.
func (n *Node) Records() *relay.RecordStore {
	return n.records
}

// SetStaticDNS installs/replaces the static _dmcn records the resolver consults before real DNS.
// Useful when the fleet's seed multiaddrs are only known after the nodes are listening (dev cluster
// generation, tests). Set once before the node serves lookups.
func (n *Node) SetStaticDNS(m map[string]domainverify.Record) {
	n.staticDNS = lowerDNSMap(m)
}

// MergeStaticDNS adds/overwrites entries in the static _dmcn map, preserving existing ones. It lets
// a serving node register its OWN domain's anchor at boot without clobbering operator-configured peer
// domains (the DHT-free federation seed-pin). Not safe for concurrent use — call during setup.
func (n *Node) MergeStaticDNS(m map[string]domainverify.Record) {
	merged := map[string]domainverify.Record{}
	for k, v := range n.staticDNS {
		merged[k] = v
	}
	for k, v := range lowerDNSMap(m) {
		merged[k] = v
	}
	n.staticDNS = merged
}

func (n *Node) Relay() *relay.Relay {
	return n.relay
}

// Keystore returns the encrypted keystore. May be nil if no keystore path
// was configured.
func (n *Node) Keystore() *keystore.Keystore {
	return n.keystore
}

// PeerID returns the node's libp2p peer ID.
func (n *Node) PeerID() peer.ID {
	return n.host.ID()
}

// Addrs returns the node's listen multiaddrs with peer ID included.
func (n *Node) Addrs() []string {
	hostAddr := n.host.Addrs()
	peerInfo := peer.AddrInfo{
		ID:    n.host.ID(),
		Addrs: hostAddr,
	}
	addrs, err := peer.AddrInfoToP2pAddrs(&peerInfo)
	if err != nil {
		return nil
	}
	result := make([]string, len(addrs))
	for i, a := range addrs {
		result[i] = a.String()
	}
	return result
}

// WaitForPeers blocks until the node has at least one connected mesh peer, or the timeout elapses.
// A short-lived process (e.g. a CLI command) that has just dialed its bootstrap node needs a moment
// before the connection is up; calling this before a resolve/publish avoids racing the dial. (This
// was a DHT-routing-table wait; with the DHT gone it is a plain connectivity wait.)
func (n *Node) WaitForPeers(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if len(n.host.Network().Peers()) > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("node: timed out waiting for mesh peers: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// ConnectPeer connects to a peer by multiaddr string.
func (n *Node) ConnectPeer(addr string) error {
	ma, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return fmt.Errorf("node: invalid peer address: %w", err)
	}

	peerInfo, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return fmt.Errorf("node: parse peer info: %w", err)
	}

	// A self-entry (e.g. a hand-edited DMCN_NODE_PEERS that lists this host) is a
	// no-op, not an error — skip it rather than letting libp2p reject the self-dial.
	if peerInfo.ID == n.host.ID() {
		return nil
	}

	if err := n.host.Connect(n.ctx, *peerInfo); err != nil {
		return fmt.Errorf("node: connect: %w", err)
	}

	return nil
}

// RelayHints returns the node's own addresses, suitable for populating
// IdentityRecord.RelayHints. Advertisement is decoupled from the infra peer list:
// a record advertises only the relay(s) that actually host its mailbox, not every
// peer the node connects to. (Smarter multi-relay placement is a planned follow-up.)
func (n *Node) RelayHints() []string {
	return n.Addrs()
}

// ParseRelayHint parses a relay hint multiaddr string into peer.AddrInfo.
func ParseRelayHint(hint string) (*peer.AddrInfo, error) {
	ma, err := multiaddr.NewMultiaddr(hint)
	if err != nil {
		return nil, fmt.Errorf("invalid relay hint: %w", err)
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return nil, fmt.Errorf("parse relay hint peer info: %w", err)
	}
	return info, nil
}

// allowPeer reports whether the federation policy permits a peer. The policy is
// always set by New; the nil guard keeps zero-value Nodes (tests) permissive.
func (n *Node) allowPeer(p peer.ID) bool {
	return n.policy == nil || n.policy.Allow(peerpolicy.PeerContext{ID: p})
}

// lowerSet builds a lowercased lookup set from a slice (nil for an empty input).
func lowerSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, s := range items {
		if s = strings.TrimSpace(strings.ToLower(s)); s != "" {
			m[s] = true
		}
	}
	return m
}

// discoverPeers queries connected peers for the full cluster list
// and connects to any newly discovered peers.
func (n *Node) discoverPeers(ctx context.Context, initialPeers []string) {
	known := make(map[string]bool)
	for _, p := range initialPeers {
		known[p] = true
	}

	for _, peerAddr := range initialPeers {
		info, err := ParseRelayHint(peerAddr)
		if err != nil {
			continue
		}
		// Skip a self-entry: don't dial or run the peer-discovery query against our
		// own ID (ConnectPeer also no-ops self, but we must not query ourselves).
		if info.ID == n.host.ID() {
			continue
		}

		// Connect using the full multiaddr first, so the peer's address is in
		// the peerstore (and the DHT routing table) before we query it by peer ID.
		// Otherwise a CLI/client node — whose only seed is its --node peer —
		// dials the other peers by ID with no known address ("no addresses")
		// and never reaches them, so records register/resolve on a single node.
		if err := n.ConnectPeer(peerAddr); err != nil {
			n.log.Warnf("failed to connect to peer %s: %v", peerAddr, err)
			continue
		}

		discovered, err := n.relay.ClientPeers(ctx, info.ID)
		if err != nil {
			n.log.Warnf("failed to discover peers from %s: %v", peerAddr, err)
			continue
		}

		for _, dp := range discovered {
			if known[dp] {
				continue
			}
			known[dp] = true
			// A discovered peer is only as trustworthy as the peer that
			// reported it; gate it against the federation policy before trusting
			// or dialing it.
			if dinfo, err := ParseRelayHint(dp); err != nil || !n.allowPeer(dinfo.ID) {
				n.log.Warnf("discovered peer %s rejected by federation policy", dp)
				continue
			}
			n.peers = append(n.peers, dp)
			if err := n.ConnectPeer(dp); err != nil {
				n.log.Warnf("failed to connect to discovered peer %s: %v", dp, err)
			}
		}
	}
}

// Close shuts down the node, stopping the relay and registry. The persistent
// datastore is closed last (the node owns it; nothing must write after).
func (n *Node) Close() error {
	n.cancel()
	n.wg.Wait() // let background loops finish before tearing down their dependencies
	n.relay.Stop()
	n.registry.Close()
	n.host.Close()
	if n.datastore != nil {
		n.datastore.Close()
	}
	return nil
}
