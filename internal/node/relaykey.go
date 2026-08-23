package node

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	corecrypto "dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/relay"
)

// IssuerKeyPair returns an identity.IdentityKeyPair backed by the node's single libp2p
// Ed25519 key — the same key that is the node's peer ID and the Subject of its join
// credential. Used to issue (sign) sub-credentials (address/routing) when this peer's own
// credential carries the matching grant, so issuance uses one key, not a separate online
// signing key. Only the Ed25519 halves are populated; Credential.Sign uses only Ed25519, so
// the X25519 halves are intentionally left zero.
func (n *Node) IssuerKeyPair() (*identity.IdentityKeyPair, error) {
	priv := n.host.Peerstore().PrivKey(n.host.ID())
	if priv == nil {
		return nil, fmt.Errorf("node: host private key unavailable")
	}
	raw, err := priv.Raw()
	if err != nil {
		return nil, fmt.Errorf("node: extract host key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("node: host key is not an inlined ed25519 key (len %d)", len(raw))
	}
	sk := ed25519.PrivateKey(raw)
	return &identity.IdentityKeyPair{
		Ed25519Private: sk,
		Ed25519Public:  sk.Public().(ed25519.PublicKey),
	}, nil
}

// relayKeyFile is the filename, under DataDir, of a relay node's persisted onion
// X25519 keypair (priv||pub, 64 bytes).
const relayKeyFile = "relay-x25519.key"

// loadOrCreateRelayX25519Key returns the node's onion-routing X25519 keypair.
// When dataDir is set it persists priv||pub at dataDir/relay-x25519.key so the
// published RelayDescriptor is stable across restarts; with no dataDir it returns
// an ephemeral pair (the descriptor changes each run — fine for dev).
func loadOrCreateRelayX25519Key(dataDir string) (priv [32]byte, pub [32]byte, err error) {
	return loadOrCreateX25519KeyFile(dataDir, relayKeyFile)
}

// loadOrCreateX25519KeyFile load-or-creates a persisted X25519 keypair stored as
// priv||pub (64 bytes) at dataDir/filename. With no dataDir it returns an
// ephemeral pair. A corrupt file errors rather than silently regenerating.
func loadOrCreateX25519KeyFile(dataDir, filename string) (priv [32]byte, pub [32]byte, err error) {
	if dataDir != "" {
		path := filepath.Join(dataDir, filename)
		data, rerr := os.ReadFile(path)
		switch {
		case rerr == nil:
			if len(data) != 64 {
				return priv, pub, fmt.Errorf("node: key %s is corrupt (delete it to regenerate)", path)
			}
			copy(priv[:], data[:32])
			copy(pub[:], data[32:])
			return priv, pub, nil
		case !errors.Is(rerr, fs.ErrNotExist):
			return priv, pub, fmt.Errorf("node: read key %s: %w", filename, rerr)
		}
	}

	gpub, gpriv, gerr := corecrypto.GenerateX25519KeyPair()
	if gerr != nil {
		return priv, pub, fmt.Errorf("node: generate key: %w", gerr)
	}
	priv, pub = gpriv, gpub

	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return priv, pub, fmt.Errorf("node: create key dir: %w", err)
		}
		buf := append(append([]byte{}, priv[:]...), pub[:]...)
		if err := os.WriteFile(filepath.Join(dataDir, filename), buf, 0o600); err != nil {
			return priv, pub, fmt.Errorf("node: write key %s: %w", filename, err)
		}
	}
	return priv, pub, nil
}

// mailboxFilterKeyFile is the filename, under DataDir, of a mailbox node's
// persisted X25519 key that opens recipient mail-filter lists for enforcement.
const mailboxFilterKeyFile = "mailbox-filter-x25519.key"

// loadOrCreateMailboxFilterKey returns the mailbox node's X25519 keypair used to
// decrypt recipients' (dual-sealed) mail-filter lists. Persisted under DataDir so
// the key — and thus the ability to read stored filters — survives restarts.
func loadOrCreateMailboxFilterKey(dataDir string) (priv [32]byte, pub [32]byte, err error) {
	return loadOrCreateX25519KeyFile(dataDir, mailboxFilterKeyFile)
}

// RelayX25519Pub returns this node's onion-routing public key (advertised in its
// RelayDescriptor).
func (n *Node) RelayX25519Pub() [32]byte { return n.relayX25519Pub }

// MailboxFilterPub returns the relay's mailbox X25519 public key — clients seal
// their filter list to this (alongside their own key) so the mailbox can enforce
// it. Zero for non-mailbox nodes.
func (n *Node) MailboxFilterPub() [32]byte { return n.mailboxFilterPub }

// MailFilterStore returns the node's recipient filter store (nil unless this node
// hosts mailboxes). Used by the owner-facing API to get/put sealed filter blobs.
func (n *Node) MailFilterStore() *relay.PersistentMailFilterStore { return n.mailFilterStore }

// RelayX25519Priv returns this node's onion-routing private key, used by the
// onion-forward handler to peel its layer.
func (n *Node) RelayX25519Priv() [32]byte { return n.relayX25519Priv }

// relayRepublishInterval is how often a relay re-publishes its descriptor and
// re-announces its provider records. The provider record's TTL outlives this so a
// live relay is continuously discoverable; a relay that stops (crash, shutdown)
// stops re-announcing, and its provider record expires — the liveness "canary".
const relayRepublishInterval = 30 * time.Minute

// buildSignedDescriptor constructs the node's current RelayDescriptor carrying its node
// credential (Credential PKI), and self-signs it with the libp2p key. Re-run on each
// republish so revision/CreatedAt refresh (freshness). Returns nil if the host key is
// missing.
func (n *Node) buildSignedDescriptor() *identity.RelayDescriptor {
	priv := n.host.Peerstore().PrivKey(n.host.ID())
	if priv == nil {
		n.log.Warnf("relay descriptor: host private key unavailable; not publishing onion key")
		return nil
	}
	desc := &identity.RelayDescriptor{
		PeerID:       n.host.ID().String(),
		X25519Public: n.relayX25519Pub,
		Multiaddrs:   n.Addrs(),
		CreatedAt:    time.Now().UTC(),
		Revision:     uint64(time.Now().Unix()), // monotonic across restarts
		Domain:       n.domain,
	}
	// Credential PKI: carry our credential so route selection — and outbound-bridge discovery
	// — can verify us without connecting first (Subject == our peer ID, so it cannot be
	// swapped). One key per peer means one credential, which may carry several roles: a node
	// that is also this domain's SMTP bridge advertises a single credential granting both.
	if n.credential != nil {
		desc.Credential = n.credential
	}
	signable, err := desc.SignableBytes()
	if err != nil {
		n.log.Warnf("relay descriptor: marshal: %v", err)
		return nil
	}
	sig, err := priv.Sign(signable)
	if err != nil {
		n.log.Warnf("relay descriptor: sign: %v", err)
		return nil
	}
	desc.Signature = sig
	return desc
}

// publishRelayDescriptor refreshes this relay's signed onion descriptor in its local RecordStore
// (signed by the node's libp2p identity key, verifiable from the peer ID); peers fetch it via the
// relay GetRelayDescriptor fleet op. Runs in the background on an interval so the descriptor's
// revision stays fresh. No DHT.
// announceDomains is the set of domains this node serves as a relay for: every credential domain it
// holds, plus the operator-permitted (concrete) customer domains — so a hosted customer's placement
// discovers this fleet relay. Falls back to the primary domain.
func (n *Node) announceDomains() []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		out = append(out, d)
	}
	for _, b := range n.joinBundles {
		if b.Credential != nil {
			add(b.Credential.Domain)
		}
	}
	// NOTE (open-dmcn): fleet operator permits are omitted; a single self-hosted domain
	// announces under its own domain.
	if len(out) == 0 {
		add(n.domain)
	}
	return out
}

// SetDescriptorCredential sets the credential this node advertises in its RelayDescriptor and
// republishes immediately.
//
// It exists because some credentials cannot be known at node.New time. A self-hosted daemon
// receives its domain's authority record over the wire after startup, and only then can load the
// `bridge` credential anchored on it — but the descriptor was already published, so without a
// republish the node would advertise no credential and be undiscoverable as a bridge until the
// 30-minute refresh.
//
// A peer that is both a relay and a bridge should hold ONE credential carrying both roles, so
// replacing a credential that has roles the new one lacks is almost always a misconfiguration
// rather than an intent, and says so.
func (n *Node) SetDescriptorCredential(cred *identity.Credential) {
	if cred == nil {
		return
	}
	if old := n.credential; old != nil {
		for _, r := range old.Roles {
			if !cred.HasRole(r) {
				n.log.Warnf("replacing this node's advertised credential drops the %q role; "+
					"a peer that is both a relay and a bridge wants a single credential granting both", r)
			}
		}
	}
	n.credential = cred
	if desc := n.buildSignedDescriptor(); desc != nil && n.records != nil {
		if err := n.records.PutRelayDescriptor(n.ctx, desc); err != nil {
			n.log.Warnf("relay descriptor: republish after credential change failed: %v", err)
			return
		}
		n.log.Successf("relay descriptor republished with the %v credential", cred.Roles)
	}
}

func (n *Node) publishRelayDescriptor() {
	first := true
	ticker := time.NewTicker(relayRepublishInterval)
	defer ticker.Stop()
	for {
		// Refresh the fleet-served descriptor in the local RecordStore (revision bumps on each
		// rebuild); peers fetch it via the relay GetRelayDescriptor op. No DHT publish.
		if desc := n.buildSignedDescriptor(); desc != nil && n.records != nil {
			if err := n.records.PutRelayDescriptor(n.ctx, desc); err != nil {
				if first {
					n.log.Warnf("relay descriptor: store failed: %v", err)
				}
			} else if first {
				n.log.Successf("relay descriptor stored (onion routing)")
			}
		}
		first = false
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
