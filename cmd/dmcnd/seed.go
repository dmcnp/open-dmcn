package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/keystore"
	"dmcn.dev/open-dmcn/internal/node"
)

// seed.go brings up the daemon's one domain. Where the domain root key lives is the difference
// between the two modes, and it is the whole security posture of a live deployment:
//
//   - DEV mints the root here, on the node, and signs with it at runtime. That is what makes
//     one-command dev mode possible, and it is exactly the thing you must not do for real: the
//     root is the trust anchor every other domain checks your records against, so a box that
//     holds it is a box that can mint any address on your domain the moment it is breached.
//
//   - LIVE never sees the root. The operator mints it on their own machine, signs the domain
//     authority record there, and pushes that record to the node over libp2p — the same way
//     `remove-address` pushes a tombstone. The node stores it, serves the domain, and cannot
//     issue anything for it. New addresses need the offline root, which is what the petition
//     queue arranges.
//
// Accounts are NOT created here in either mode. A browser generates its own keypair, self-signs
// its identity record, and sends only the signed public record; the daemon never holds an
// account private key.

// seedStore holds the DEV domain root key, encrypted at rest. A live daemon never constructs one
// — there is no long-term secret for it to hold. (The bridge used to keep its identity here too;
// it now derives its keys from the node, see bridgeInfraKeys.)
type seedStore struct{ ks *keystore.Keystore }

// rootAlias is the reserved keystore key under which the DEV domain authority (root) key is
// persisted. It is not a real address, so it can never collide with anything else.
func rootAlias(domain string) string { return "__domain_root__@" + domain }

func newSeedStore(dataDir, passphrase string) *seedStore {
	return &seedStore{ks: keystore.New(filepath.Join(dataDir, "seed-keystore.json"), passphrase)}
}

// loadOrCreate returns the keypair stored under key, minting + persisting a fresh one the
// first time. created reports whether a new key was generated.
func (s *seedStore) loadOrCreate(key string) (kp *identity.IdentityKeyPair, created bool, err error) {
	kp, err = s.ks.Load(key)
	switch {
	case err == nil:
		return kp, false, nil
	case errors.Is(err, keystore.ErrNotFound):
		kp, err = identity.GenerateIdentityKeyPair()
		if err != nil {
			return nil, false, fmt.Errorf("generate %s: %w", key, err)
		}
		if err := s.ks.Store(key, kp); err != nil {
			return nil, false, fmt.Errorf("persist %s: %w", key, err)
		}
		return kp, true, nil
	default:
		return nil, false, fmt.Errorf("load %s: %w", key, err)
	}
}

// seedDomainDev mints (or reloads) the domain root key ON THIS NODE, signs + publishes the
// domain's DAR, and anchors the node's static _dmcn at itself. It returns the root key so dev
// mode can sign routing credentials for self-service registrations.
//
// Dev only. On a live domain the root is never here, so there is nothing to return.
func (s *seedStore) seedDomainDev(ctx context.Context, n *node.Node, domain string, at time.Time) (*identity.IdentityKeyPair, error) {
	rootKP, created, err := s.loadOrCreate(rootAlias(domain))
	if err != nil {
		return nil, err
	}

	dar, err := identity.NewDomainAuthorityRecord(domain, rootKP, at)
	if err != nil {
		return nil, fmt.Errorf("build DAR for %s: %w", domain, err)
	}
	if err := dar.Sign(rootKP); err != nil {
		return nil, fmt.Errorf("sign DAR for %s: %w", domain, err)
	}
	if _, err := n.PublishDAR(ctx, dar); err != nil {
		return nil, fmt.Errorf("publish DAR for %s: %w", domain, err)
	}
	if err := anchorSelf(n, domain, dar.Fingerprint(), false); err != nil {
		return nil, err
	}

	log.Infof("seeded domain %s (root %s, DAR fp %s)%s",
		domain, shortHex(rootKP.Ed25519Public), dar.Fingerprint(), createdNote(created))
	return rootKP, nil
}

// anchorSelf points the node's static _dmcn for its own domain at this node, so the resolver can
// verify records it is authoritative for.
//
// asBridge additionally advertises this node as the domain's outbound bridge. That is what lets
// this daemon's own users send to ordinary email: a sender discovers the bridge by reading
// `bridge=` from the domain's _dmcn record, and on a single-binary self-host the only node
// available to answer is this one. In a real deployment the same token goes in real DNS; this is
// the local mirror of it.
func anchorSelf(n *node.Node, domain, fingerprint string, asBridge bool) error {
	addrs := n.Addrs()
	if len(addrs) == 0 {
		return fmt.Errorf("node has no dialable address to anchor %s", domain)
	}
	// Addrs() already returns fully-qualified /p2p/<peerID> multiaddrs (peer.AddrInfoToP2pAddrs),
	// so appending the peer ID again produced ".../p2p/<id>/p2p/<id>" — malformed, and previously
	// invisible because a node resolving its OWN domain never dialled the result. It is visible
	// now: the same value is handed to senders as this domain's bridge= endpoint.
	self := addrs[0]
	rec := domainverify.Record{Fingerprint: fingerprint, Seeds: []string{self}}
	if asBridge {
		rec.Bridges = []string{self}
	}
	// Merge (don't replace) so operator-configured peer domains (DMCND_STATIC_DNS, for
	// federation) survive alongside this node's own-domain anchor.
	n.MergeStaticDNS(map[string]domainverify.Record{domain: rec})
	return nil
}

// seedIdentity load-or-creates the keypair for address, self-signs its record, attaches an
// operator routing credential (RelayHints = this node, signed by the domain root), and
// publishes it.
//
// TEST-ONLY, and dev-only by construction: it needs a root key, which a live daemon does not
// have. It mints an account keypair server-side, which is exactly what the daemon does not do in
// normal operation — accounts come from the browser. It survives here because the end-to-end
// tests need to stand up two accounts without driving a browser. Do not wire it to a flag, an
// env var or a CLI command: that would put account private keys back on the server and make the
// daemon's zero-knowledge claim untrue again.
func (s *seedStore) seedIdentity(ctx context.Context, n *node.Node, rootKP *identity.IdentityKeyPair, address string, at time.Time) (*identity.IdentityKeyPair, error) {
	kp, created, err := s.loadOrCreate(address)
	if err != nil {
		return nil, err
	}

	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		return nil, fmt.Errorf("build record for %s: %w", address, err)
	}
	if err := rec.Sign(kp); err != nil {
		return nil, fmt.Errorf("sign record for %s: %w", address, err)
	}
	// RelayHints are operator-owned. On a single self-hosted node the only home is this
	// node, so the routing credential (signed by the domain root) points at the node's own
	// dialable address(es). This mirrors what an operator's issuer would attest at scale.
	hints := n.RelayHints()
	if len(hints) == 0 {
		return nil, fmt.Errorf("node has no relay hint to route %s", address)
	}
	if err := rec.IssueRoutingCredential(rootKP, hints, at); err != nil {
		return nil, fmt.Errorf("issue routing credential for %s: %w", address, err)
	}
	if _, err := n.PublishIdentity(ctx, rec); err != nil {
		return nil, fmt.Errorf("publish record for %s: %w", address, err)
	}

	log.Infof("seeded identity %s (key %s)%s", address, shortHex(kp.Ed25519Public), createdNote(created))
	return kp, nil
}

// bridgeInfraKeys gives the SMTP bridge its keys, derived entirely from the node.
//
// The bridge is not a separate peer here — it is folded into this process — so it does not get a
// key of its own. Its Ed25519 half is the node's libp2p key (the peer ID's key, and the subject of
// any credential the node holds) and its X25519 half is the node's relay key. This mirrors the
// product's bridge, which is pure infrastructure trusted through its own credential rather than
// through a secret in a keystore.
//
// It matters beyond tidiness: with this, a LIVE daemon holds no keystore at all. There is no
// seed-keystore.json and DMCND_SEED_PASSPHRASE stops applying to anything, so the only long-term
// secrets on the box are the node key and the two transport keys.
func bridgeInfraKeys(n *node.Node) (*identity.IdentityKeyPair, error) {
	kp, err := n.IssuerKeyPair() // Ed25519 halves == the peer ID's key
	if err != nil {
		return nil, fmt.Errorf("bridge infra keys: %w", err)
	}
	kp.X25519Public = n.RelayX25519Pub()
	kp.X25519Private = n.RelayX25519Priv()
	copy(kp.DeviceID[:], kp.Ed25519Public[:16]) // stable opaque device label
	return kp, nil
}

func createdNote(created bool) string {
	if created {
		return " [new]"
	}
	return ""
}

func shortHex(b []byte) string {
	if len(b) > 6 {
		b = b[:6]
	}
	return fmt.Sprintf("%x", b)
}
