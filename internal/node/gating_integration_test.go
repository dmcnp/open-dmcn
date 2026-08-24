package node_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/node"
)

// nodeIdentity creates a persistent identity key and returns its path and the
// derived peer ID, so a peer can be allowlisted before the node is started.
func nodeIdentity(t *testing.T, dir, name string) (keyPath string, id peer.ID) {
	t.Helper()
	keyPath = filepath.Join(dir, name+".key")
	priv, err := node.LoadOrCreateIdentityKey(keyPath)
	if err != nil {
		t.Fatalf("identity key %s: %v", name, err)
	}
	id, err = peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("derive id %s: %v", name, err)
	}
	return keyPath, id
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestFederationGating verifies credential-gated participation (deny-by-default). There is no
// hard connection gater anymore, so connections are OPEN — but a peer that is neither in the
// static allow-set nor credentialed never gains PARTICIPATION (peer discovery + relay streams).
// A and B allowlist each other (the static escape hatch); C (open) is admitted by neither even
// though it can connect.
func TestFederationGating(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dir := t.TempDir()
	aKey, aID := nodeIdentity(t, dir, "a")
	bKey, bID := nodeIdentity(t, dir, "b")
	cKey, cID := nodeIdentity(t, dir, "c")

	nA, err := node.New(ctx, node.Config{ListenAddr: "/ip4/127.0.0.1/tcp/0", IdentityKeyPath: aKey, AllowedPeers: []string{bID.String()}})
	if err != nil {
		t.Fatalf("create A: %v", err)
	}
	defer nA.Close()
	nB, err := node.New(ctx, node.Config{ListenAddr: "/ip4/127.0.0.1/tcp/0", IdentityKeyPath: bKey, AllowedPeers: []string{aID.String()}})
	if err != nil {
		t.Fatalf("create B: %v", err)
	}
	defer nB.Close()
	nC, err := node.New(ctx, node.Config{ListenAddr: "/ip4/127.0.0.1/tcp/0", IdentityKeyPath: cKey, AllowedPeers: []string{"*"}})
	if err != nil {
		t.Fatalf("create C: %v", err)
	}
	defer nC.Close()

	// A connects to B (mutually allowlisted).
	if err := nA.ConnectPeer(nB.Addrs()[0]); err != nil {
		t.Fatalf("connect A→B failed: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		return nA.Host().Network().Connectedness(bID) == network.Connected
	}) {
		t.Fatal("A and B should be connected")
	}

	// Connections are open: C (un-allowlisted, un-credentialed) CAN establish a connection to A
	// — gating is at participation, not at the connection.
	if err := nC.ConnectPeer(nA.Addrs()[0]); err != nil {
		t.Fatalf("open connection C→A should succeed (no hard gater): %v", err)
	}

	// Participation gating (deny-by-default): B (allowlisted) is admitted to A's federation; C
	// (neither allowlisted nor credentialed) never is, even while connected.
	if !waitFor(3*time.Second, func() bool { return nA.Admitted(bID) }) {
		t.Error("allowlisted peer B should be admitted to A's federation")
	}
	if waitFor(time.Second, func() bool { return nA.Admitted(cID) }) {
		t.Error("un-credentialed peer C must NOT be admitted (participation denied)")
	}
}

// TestFederationOpenMode verifies the "*" sentinel restores open connectivity.
func TestFederationOpenMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nA, err := node.New(ctx, node.Config{ListenAddr: "/ip4/127.0.0.1/tcp/0", AllowedPeers: []string{"*"}})
	if err != nil {
		t.Fatalf("create A: %v", err)
	}
	defer nA.Close()
	nB, err := node.New(ctx, node.Config{ListenAddr: "/ip4/127.0.0.1/tcp/0", AllowedPeers: []string{"*"}})
	if err != nil {
		t.Fatalf("create B: %v", err)
	}
	defer nB.Close()

	if err := nA.ConnectPeer(nB.Addrs()[0]); err != nil {
		t.Fatalf("open-mode connect failed: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		return nA.Host().Network().Connectedness(nB.PeerID()) == network.Connected
	}) {
		t.Fatal("open-mode nodes should connect")
	}
}
