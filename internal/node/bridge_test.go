package node

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// bridge_test.go covers outbound-bridge discovery: `bridge=` in _dmcn finds a candidate, and its
// credential decides whether anything is sealed to it.
//
// The credential half is the part that matters. A relay only ever holds sealed envelopes, but a
// bridge decrypts outbound mail to hand it to SMTP — so answering a bridge= token means reading
// the plaintext. Discovery that trusted DNS alone would let whoever controls a domain's DNS read
// its outbound mail.

const bdDomain = "mesh.example"

func newBridgeTestNode(t *testing.T) *Node {
	t.Helper()
	n, err := New(context.Background(), Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       bdDomain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// anchorWithBridge writes a static _dmcn record advertising addr as the domain's bridge.
func anchorWithBridge(n *Node, bridgeAddr string) {
	n.MergeStaticDNS(map[string]domainverify.Record{
		bdDomain: {Fingerprint: "FP", Seeds: []string{bridgeAddr}, Bridges: []string{bridgeAddr}},
	})
}

func selfAddr(t *testing.T, n *Node) string {
	t.Helper()
	addrs := n.Addrs()
	if len(addrs) == 0 {
		t.Fatal("node has no address")
	}
	return addrs[0] + "/p2p/" + n.PeerID().String()
}

// TestResolveBridgeFindsItself is the single-binary case, which is what a self-host actually runs:
// one process is the relay and the bridge, and a host cannot dial itself. Discovery has to answer
// from local state rather than deadlocking on a self-dial.
func TestResolveBridgeFindsItself(t *testing.T) {
	n := newBridgeTestNode(t)
	anchorWithBridge(n, selfAddr(t, n))

	ep, err := n.ResolveBridge(context.Background(), bdDomain)
	if err != nil {
		t.Fatalf("ResolveBridge: %v", err)
	}
	if ep.PeerID != n.PeerID().String() {
		t.Errorf("resolved peer %s, want self %s", ep.PeerID, n.PeerID())
	}
	if ep.X25519Public != n.RelayX25519Pub() {
		t.Error("resolved the wrong sealing key — outbound mail would be unreadable by the bridge")
	}
}

// TestResolveBridgeNeedsATokenKeeps a domain with no bridge honest: it cannot send to legacy mail,
// and the error says so rather than failing later somewhere less obvious.
func TestResolveBridgeNeedsAToken(t *testing.T) {
	n := newBridgeTestNode(t)
	n.MergeStaticDNS(map[string]domainverify.Record{
		bdDomain: {Fingerprint: "FP", Seeds: []string{selfAddr(t, n)}},
	})

	_, err := n.ResolveBridge(context.Background(), bdDomain)
	if err == nil {
		t.Fatal("resolved a bridge for a domain advertising none")
	}
	if !strings.Contains(err.Error(), "bridge=") {
		t.Errorf("the error does not name the missing token: %v", err)
	}
}

// TestResolveBridgeRejectsAnImpostor is the security property. A peer that answers a bridge= token
// but cannot present a `bridge` credential for the domain must be refused BEFORE anything is
// sealed to it — otherwise poisoning a DNS record would be enough to read a domain's outbound mail.
func TestResolveBridgeRejectsAnImpostor(t *testing.T) {
	sender := newBridgeTestNode(t)
	impostor := newBridgeTestNode(t) // running, reachable, but holds no bridge credential
	anchorWithBridge(sender, selfAddr(t, impostor))

	_, err := sender.ResolveBridge(context.Background(), bdDomain)
	if err == nil {
		t.Fatal("a peer with no bridge credential was accepted as a bridge")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}
}

// TestVerifyBridgeCredentialRequiresTheRole stops any credential the root ever issued from being
// reused as bridge authority — a routing credential is not permission to read outbound mail.
func TestVerifyBridgeCredentialRequiresTheRole(t *testing.T) {
	n := newBridgeTestNode(t)
	root, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pid := n.PeerID()
	pub, _ := pid.ExtractPublicKey()
	raw, _ := pub.Raw()

	mk := func(roles ...string) *identity.RelayDescriptor {
		c := &identity.Credential{
			Version: 1, Subject: ed25519.PublicKey(raw), Domain: bdDomain,
			Roles: roles, IssuedAt: time.Now().UTC(),
		}
		if serr := c.Sign(root); serr != nil {
			t.Fatal(serr)
		}
		return &identity.RelayDescriptor{PeerID: pid.String(), Credential: c}
	}

	if err := n.verifyBridgeCredential(context.Background(), mk(identity.RoleRouting), pid); err == nil {
		t.Error("a routing credential was accepted as bridge authority")
	} else if !strings.Contains(err.Error(), "bridge role") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}

	// A credential for a DIFFERENT subject must not pass either, even carrying the right role —
	// credentials are public and travel in the open, so they can be copied.
	other, _ := identity.GenerateIdentityKeyPair()
	stolen := mk(identity.RoleBridge)
	stolen.Credential.Subject = other.Ed25519Public
	if err := n.verifyBridgeCredential(context.Background(), stolen, pid); err == nil {
		t.Error("a credential naming a different peer was accepted")
	}

	// And one with no credential at all.
	if err := n.verifyBridgeCredential(context.Background(), &identity.RelayDescriptor{PeerID: pid.String()}, pid); err == nil {
		t.Error("a descriptor with no credential was accepted")
	}
}
