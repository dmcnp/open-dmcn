package node_test

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// TestClientOnlyNode verifies a client-only node: it can register and look up
// records and use relay client methods against a server, but does
// not serve the relay protocol itself (no server-side handler registered).
func TestClientOnlyNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := fleetNode(t, ctx)
	defer server.Close()

	client, err := node.New(ctx, node.Config{
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		Peers:        []string{server.Addrs()[0]},
		AllowedPeers: []string{"*"},
		ClientOnly:   true,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	if !waitFor(3*time.Second, func() bool {
		return client.Host().Network().Connectedness(server.PeerID()) == network.Connected
	}) {
		t.Fatal("client should connect to server")
	}

	// Client lookups work: the client registers an identity and the server resolves it.
	if err := client.WaitForPeers(ctx, 5*time.Second); err != nil {
		t.Fatalf("client wait for peers: %v", err)
	}
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord("alice@localhost", kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	putRec(t, ctx, rec, server)
	if found, err := server.Registry().Lookup(ctx, "alice@localhost"); err != nil {
		t.Fatalf("server lookup of client-registered record: %v", err)
	} else if found.Fingerprint() != rec.Fingerprint() {
		t.Error("looked-up record fingerprint differs")
	}

	// The client uses relay client methods against the server.
	if _, err := client.Relay().ClientPing(ctx, server.PeerID()); err != nil {
		t.Errorf("client relay ping to server should succeed: %v", err)
	}

	// The client serves no relay handler: pinging it over the relay protocol fails.
	if _, err := server.Relay().ClientPing(ctx, client.PeerID()); err == nil {
		t.Error("a client-only node must not answer relay streams")
	}
}
