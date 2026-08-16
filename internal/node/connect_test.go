package node_test

import (
	"context"
	"testing"

	"dmcn.dev/open-dmcn/internal/node"
)

// TestConnectPeerSelfIsNoOp verifies that dialing this node's own multiaddr — e.g. a
// hand-edited DMCN_NODE_PEERS that happens to list this host — is a no-op rather than a
// libp2p "dial to self" rejection. ConnectPeer is the single choke point every peer
// dialer (startMesh, discoverPeers, maintainPeers) goes through.
func TestConnectPeerSelfIsNoOp(t *testing.T) {
	ctx := context.Background()
	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		ClientOnly:   true,
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.Close()

	selfAddrs := n.Addrs()
	if len(selfAddrs) == 0 {
		t.Skip("node has no dialable addrs in this environment")
	}
	for _, self := range selfAddrs {
		if err := n.ConnectPeer(self); err != nil {
			t.Fatalf("ConnectPeer(self=%s) should be a no-op, got: %v", self, err)
		}
	}
}
