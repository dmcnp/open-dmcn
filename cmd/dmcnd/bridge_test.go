package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/node"
)

// TestBridgeFold proves the P4 fold: the SMTP bridge shares the daemon's node, and an inbound
// legacy email addressed to the bridge domain is translated, signed+encrypted, and delivered into
// the recipient's DMCN mailbox ON THE SAME NODE (no self-dial). The recipient is a normally-seeded
// identity, so this exercises the whole shared-node path end-to-end.
func TestBridgeFold(t *testing.T) {
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx := context.Background()
	const dmcnDomain = "localhost"
	const bridgeDomain = "bridge.localhost"

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       dmcnDomain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.Close()

	seeds := newSeedStore(t.TempDir(), "test-pass")
	now := time.Now()
	rootKP, err := seeds.seedDomain(ctx, n, dmcnDomain, now)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	// The recipient of the bridged mail (a normal DMCN account).
	aliceKP, err := seeds.seedIdentity(ctx, n, rootKP, "alice@"+dmcnDomain, now)
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	// The bridge's own identity (BridgeCapability + routing credential).
	bridgeKP, err := seeds.seedBridgeIdentity(ctx, n, rootKP, "bridge@"+dmcnDomain, now)
	if err != nil {
		t.Fatalf("seed bridge identity: %v", err)
	}

	// Fold the bridge onto the shared node. Port :0 so the SMTP listener picks a free port; we
	// drive the inbound handler directly rather than over a socket.
	br, err := bridge.New(ctx, n, bridgeKP, bridge.Config{
		SMTPListenAddr: "127.0.0.1:0",
		BridgeAddress:  "bridge@" + dmcnDomain,
		BridgeDomain:   bridgeDomain,
		DMCNDomain:     dmcnDomain,
	}, log)
	if err != nil {
		t.Fatalf("bridge.New on shared node: %v", err)
	}
	defer br.Stop()

	// An inbound legacy email to alice@<bridgeDomain> → translated to alice@<dmcnDomain>, wrapped,
	// and delivered into alice's mailbox on this node.
	raw := []byte("From: ext@gmail.com\r\nTo: alice@" + bridgeDomain + "\r\nSubject: hello\r\n\r\nhi alice from the legacy world\r\n")
	if err := br.Inbound().HandleMessage(ctx, "1.2.3.4", "ext@gmail.com", "alice@"+bridgeDomain, raw); err != nil {
		t.Fatalf("inbound HandleMessage: %v", err)
	}

	// The bridged message must be in alice's durable mailbox on the shared node.
	aliceRxHex := fmt.Sprintf("%x", aliceKP.X25519Public[:])
	count, err := n.Relay().Mailbox().Count(ctx, aliceRxHex)
	if err != nil {
		t.Fatalf("mailbox count: %v", err)
	}
	if count != 1 {
		t.Fatalf("alice mailbox count = %d, want 1 (bridged mail not delivered to the shared node)", count)
	}
}
