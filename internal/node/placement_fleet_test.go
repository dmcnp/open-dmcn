package node

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestRelayCredentialValidAcceptsFleetCred guards the placement fix: a relay advertising an
// operator-rooted FLEET `node` credential (no DAR) must validate against the configured operator
// pubkey. Before the fix relayCredentialValid verified only DAR-rooted creds, so every
// fleet-credentialed relay was filtered out of placement and HandleRelayHints/ComputeRelayHints
// returned "no mailbox relay available" even when the fleet was healthy.
func TestRelayCredentialValidAcceptsFleetCred(t *testing.T) {
	op, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := LoadOrCreateIdentityKey(filepath.Join(t.TempDir(), "relay.key"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pub.Raw()
	if err != nil {
		t.Fatal(err)
	}
	mkDesc := func(c *identity.Credential) *identity.RelayDescriptor {
		return &identity.RelayDescriptor{PeerID: pid.String(), Credential: c}
	}
	signed := func(c *identity.Credential) *identity.Credential {
		if err := c.Sign(op); err != nil {
			t.Fatal(err)
		}
		return c
	}

	n := &Node{operatorPub: op.Ed25519Public}
	ctx := context.Background()

	// The fix: an operator-rooted fleet `node` cred (Subject == peer ID, no DAR) validates.
	good := signed(&identity.Credential{Version: 1, Subject: ed25519.PublicKey(raw), Roles: []string{identity.RoleNode}, IssuedAt: time.Now()})
	if !n.relayCredentialValid(ctx, mkDesc(good)) {
		t.Fatal("a fleet-credentialed relay (operator-signed `node` cred) must validate")
	}

	// Key-binding: a cred whose Subject != the descriptor's peer ID is rejected (can't be swapped).
	wrongSubj := signed(&identity.Credential{Version: 1, Subject: ed25519.PublicKey(op.Ed25519Public), Roles: []string{identity.RoleNode}, IssuedAt: time.Now()})
	if n.relayCredentialValid(ctx, mkDesc(wrongSubj)) {
		t.Fatal("a relay cred whose Subject != peer ID must be rejected")
	}

	// Role-gating: a fleet cred without the `node` role is rejected (returns before any DAR/registry path).
	noRole := signed(&identity.Credential{Version: 1, Subject: ed25519.PublicKey(raw), Roles: []string{identity.RoleClient}, IssuedAt: time.Now()})
	if n.relayCredentialValid(ctx, mkDesc(noRole)) {
		t.Fatal("a relay cred without the `node` role must be rejected")
	}
}
