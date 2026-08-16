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

// seed.go bootstraps a single self-hosted domain for the reference daemon: a stable domain
// root key, its signed DAR, a static _dmcn anchor pointing the resolver at this node, and
// (optionally, for dev) a set of pre-provisioned identities.
//
// Real provisioning — a browser generates the keys, an admin UI registers the record — is a
// later phase. This seed exists so a fresh daemon serves mail for its domain out of the box
// and so the reference implementation is exercisable end-to-end. It is the ONLY place the
// daemon touches user private keys: they are minted here, self-sign their record, and are
// persisted (encrypted) purely so a human can import them into a browser; serving auth is the
// browser's per-op nonce signature, so the daemon never needs them at rest to run.

// seedStore holds the domain root key and any dev-seeded identity keys, encrypted at rest.
type seedStore struct{ ks *keystore.Keystore }

// rootAlias is the reserved keystore key under which the domain authority (root) key is
// persisted. It is not a real address, so it can never collide with a seeded identity.
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

// seedDomain loads-or-creates the domain root key, signs + publishes the domain's DAR, and
// points the node's static _dmcn at itself (DAR fingerprint + this node's seed) so the
// resolver can verify records the node is authoritative for. It returns the root key so
// callers can issue operator-owned credentials (e.g. routing) for the domain's addresses.
func (s *seedStore) seedDomain(ctx context.Context, n *node.Node, domain string, at time.Time) (*identity.IdentityKeyPair, error) {
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

	addrs := n.Addrs()
	if len(addrs) == 0 {
		return nil, fmt.Errorf("node has no dialable address to anchor %s", domain)
	}
	seed := fmt.Sprintf("%s/p2p/%s", addrs[0], n.PeerID())
	// Merge (don't replace) so operator-configured peer domains (DMCND_STATIC_DNS, for federation)
	// survive alongside this node's own-domain anchor.
	n.MergeStaticDNS(map[string]domainverify.Record{
		domain: {Fingerprint: dar.Fingerprint(), Seeds: []string{seed}},
	})

	log.Infof("seeded domain %s (root %s, DAR fp %s)%s",
		domain, shortHex(rootKP.Ed25519Public), dar.Fingerprint(), createdNote(created))
	// The DNS record other domains need to resolve + federate with this one. The fingerprint is
	// authoritative; add the node's PUBLIC seed multiaddr(s) — `dmcndcli dns --domain %s --seed …`
	// prints the complete record.
	log.Infof("publish for federation: _dmcn.%s TXT \"dmcn-verification=v1; fp=%s; seed=<public-multiaddr>\"",
		domain, dar.Fingerprint())
	return rootKP, nil
}

// seedIdentity load-or-creates the keypair for address, self-signs its record, attaches an
// operator routing credential (RelayHints = this node, signed by the domain root), and
// publishes it. The returned keypair is the one a browser would import to log in as address.
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

// seedBridgeIdentity provisions the SMTP bridge's own DMCN identity: like seedIdentity but the
// record carries BridgeCapability (covered by the owner self-signature) so recipients can verify
// its signed legacy-auth classification attestations. The daemon passes the returned keypair into
// bridge.New.
func (s *seedStore) seedBridgeIdentity(ctx context.Context, n *node.Node, rootKP *identity.IdentityKeyPair, address string, at time.Time) (*identity.IdentityKeyPair, error) {
	kp, created, err := s.loadOrCreate(address)
	if err != nil {
		return nil, err
	}

	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		return nil, fmt.Errorf("build bridge record for %s: %w", address, err)
	}
	rec.BridgeCapability = true
	if err := rec.Sign(kp); err != nil {
		return nil, fmt.Errorf("sign bridge record for %s: %w", address, err)
	}
	hints := n.RelayHints()
	if len(hints) == 0 {
		return nil, fmt.Errorf("node has no relay hint to route %s", address)
	}
	if err := rec.IssueRoutingCredential(rootKP, hints, at); err != nil {
		return nil, fmt.Errorf("issue routing credential for %s: %w", address, err)
	}
	if _, err := n.PublishIdentity(ctx, rec); err != nil {
		return nil, fmt.Errorf("publish bridge record for %s: %w", address, err)
	}

	log.Infof("seeded bridge identity %s (key %s)%s", address, shortHex(kp.Ed25519Public), createdNote(created))
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
