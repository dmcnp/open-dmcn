package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// newLiveNode starts a node with no domain authority — the state a live daemon boots into before
// the operator has pushed one.
func newLiveNode(t *testing.T, dataDir string) *node.Node {
	t.Helper()
	log = logr.With(logr.M("component", "dmcnd-test"))
	n, err := node.New(context.Background(), node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      dataDir,
		Mailbox:      true,
		Domain:       "mesh.example",
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// pushDAR does what `dmcndcli domain publish` does, with the root held only by the test.
func pushDAR(t *testing.T, n *node.Node, root *identity.IdentityKeyPair) *identity.DomainAuthorityRecord {
	t.Helper()
	dar, err := identity.NewDomainAuthorityRecord("mesh.example", root, root.CreatedAt.UTC())
	if err != nil {
		t.Fatal(err)
	}
	dar.PolicyFlags |= identity.PolicyRequireCountersign
	dar.ReservedLocalParts = append([]string(nil), identity.DefaultReservedLocalParts...)
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	if _, err := n.PublishDAR(context.Background(), dar); err != nil {
		t.Fatalf("publish DAR: %v", err)
	}
	return dar
}

// TestLiveDomainWaitsForItsAuthorityRecord is the bootstrap. The root is on another machine, so the
// record arrives by being pushed — which means the node must be listening first. It must not treat
// "no authority record" as "open domain": registry.AddressUsable returns nil when there is no DAR,
// so a daemon that served during this window would accept anything.
func TestLiveDomainWaitsForItsAuthorityRecord(t *testing.T) {
	n := newLiveNode(t, t.TempDir())

	// Nothing to serve yet, so it blocks rather than proceeding.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := awaitDomainAuthority(ctx, n, "mesh.example"); err == nil {
		t.Fatal("returned an authority record for a domain that has none")
	}

	// Once pushed, it returns it.
	want := pushDAR(t, n, mustKeyPair(t))
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	got, err := awaitDomainAuthority(ctx2, n, "mesh.example")
	if err != nil {
		t.Fatalf("did not pick up the pushed record: %v", err)
	}
	if got.Fingerprint() != want.Fingerprint() {
		t.Errorf("picked up fingerprint %s, want %s", got.Fingerprint(), want.Fingerprint())
	}
	if !got.RequiresCountersign() {
		t.Error("the adopted record does not require countersigning — the address gate is off")
	}
}

// TestLiveDomainSurvivesRestart is why the push is a one-time step rather than a config file: the
// record store is persistent, so a restarted daemon is authoritative immediately.
func TestLiveDomainSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	root := mustKeyPair(t)

	n1 := newLiveNode(t, dataDir)
	want := pushDAR(t, n1, root)
	n1.Close()

	n2 := newLiveNode(t, dataDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := awaitDomainAuthority(ctx, n2, "mesh.example")
	if err != nil {
		t.Fatalf("a restarted node lost its authority record: %v", err)
	}
	if got.Fingerprint() != want.Fingerprint() {
		t.Errorf("fingerprint changed across restart: %s vs %s", got.Fingerprint(), want.Fingerprint())
	}
}

// TestLiveDomainLeavesNoKeystoreOnTheNode is the property a reader most needs to be able to trust,
// and the one that would fail silently. A live daemon holds no long-term secret beyond its node and
// transport keys: no domain root, and — since the bridge derives its keys from the node — no bridge
// key either.
func TestLiveDomainLeavesNoKeystoreOnTheNode(t *testing.T) {
	dataDir := t.TempDir()
	n := newLiveNode(t, dataDir)
	dar := pushDAR(t, n, mustKeyPair(t))
	if err := adoptDomain(n, dar); err != nil {
		t.Fatalf("adopt domain: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dataDir, "seed-keystore.json")); err == nil {
		t.Fatal("the live path created a seed keystore on the node — nothing on a live domain should need one")
	}
	// And the domain really is being served, so the absence above is not just an inert no-op.
	if _, err := n.Registry().LookupDomainAuthority(context.Background(), "mesh.example"); err != nil {
		t.Fatalf("the domain was not actually adopted: %v", err)
	}
}

// TestBridgeUsesTheNodesOwnKeys pins the other half of that: the bridge is folded into this process
// rather than being a separate peer, so it takes the node's libp2p key and the node's relay key
// instead of minting one and parking it in a keystore. This mirrors the product's bridge, which is
// infrastructure trusted through a credential rather than through a stored secret.
func TestBridgeUsesTheNodesOwnKeys(t *testing.T) {
	n := newLiveNode(t, t.TempDir())

	kp, err := bridgeInfraKeys(n)
	if err != nil {
		t.Fatalf("bridgeInfraKeys: %v", err)
	}
	issuer, err := n.IssuerKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !kp.Ed25519Public.Equal(issuer.Ed25519Public) {
		t.Error("the bridge's signing key is not the node's own key")
	}
	if kp.X25519Public != n.RelayX25519Pub() {
		t.Error("the bridge's encryption key is not the node's relay key")
	}
	// Calling it twice must give the same identity, or every restart would orphan the bridge's
	// published record.
	again, err := bridgeInfraKeys(n)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Ed25519Public.Equal(kp.Ed25519Public) || again.X25519Public != kp.X25519Public {
		t.Error("bridgeInfraKeys is not stable across calls")
	}
}

// TestDevStillMintsItsOwnRoot guards the other direction: one command, no ceremony, is the reason
// dev mode exists, and tightening the live path must not cost it.
func TestDevStillMintsItsOwnRoot(t *testing.T) {
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx := context.Background()

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       "localhost",
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.Close()

	dataDir := t.TempDir()
	rootKP, err := newSeedStore(dataDir, "test-pass").seedDomainDev(ctx, n, "localhost", time.Now())
	if err != nil {
		t.Fatalf("seedDomainDev: %v", err)
	}
	if rootKP == nil {
		t.Fatal("dev mode returned no root key, so it cannot provision registrations")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "seed-keystore.json")); err != nil {
		t.Errorf("dev mode did not persist its root key: %v", err)
	}
}

func mustKeyPair(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}
