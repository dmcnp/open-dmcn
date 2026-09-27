package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
)

// foldedBridge is a daemon node with a normally-seeded account (alice@localhost) and the SMTP
// bridge folded onto it, the shape TestBridgeFold and the outbound tests share.
type foldedBridge struct {
	n        *node.Node
	aliceKP  *identity.IdentityKeyPair
	bridgeKP *identity.IdentityKeyPair
	br       *bridge.Bridge
}

const (
	foldDMCNDomain   = "localhost"
	foldBridgeDomain = "bridge.localhost"
)

func newFoldedBridge(t *testing.T, cfg bridge.Config) *foldedBridge {
	t.Helper()
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx := context.Background()

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       foldDMCNDomain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.Close() })

	seeds := newSeedStore(t.TempDir(), "test-pass")
	now := time.Now()
	rootKP, err := seeds.seedDomainDev(ctx, n, foldDMCNDomain, now)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	// A normal DMCN account: the recipient of bridged mail, and a sender of outbound mail.
	aliceKP, err := seeds.seedIdentity(ctx, n, rootKP, "alice@"+foldDMCNDomain, now)
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	// The bridge has no identity of its own: it signs with the node's key and is trusted through
	// a root-signed `bridge` credential.
	bridgeKP, err := bridgeInfraKeys(n)
	if err != nil {
		t.Fatalf("bridge infra keys: %v", err)
	}
	bridgeCred, err := bridgeCredential(n, rootKP, config{devMode: true, domain: foldDMCNDomain}, now)
	if err != nil {
		t.Fatalf("bridge credential: %v", err)
	}

	// Fold the bridge onto the shared node. Port :0 so the SMTP listener picks a free port.
	cfg.SMTPListenAddr = "127.0.0.1:0"
	cfg.BridgeAddress = n.PeerID().String()
	cfg.Credential = bridgeCred
	cfg.BridgeDomain = foldBridgeDomain
	cfg.DMCNDomain = foldDMCNDomain
	br, err := bridge.New(ctx, n, bridgeKP, cfg, log)
	if err != nil {
		t.Fatalf("bridge.New on shared node: %v", err)
	}
	t.Cleanup(func() { br.Stop() })
	return &foldedBridge{n: n, aliceKP: aliceKP, bridgeKP: bridgeKP, br: br}
}

// TestBridgeFold proves the P4 fold: the SMTP bridge shares the daemon's node, and an inbound
// legacy email addressed to the bridge domain is translated, signed+encrypted, and delivered into
// the recipient's DMCN mailbox ON THE SAME NODE (no self-dial). The recipient is a normally-seeded
// identity, so this exercises the whole shared-node path end-to-end.
func TestBridgeFold(t *testing.T) {
	ctx := context.Background()
	f := newFoldedBridge(t, bridge.Config{})

	// An inbound legacy email to alice@<bridgeDomain> → translated to alice@<dmcnDomain>, wrapped,
	// and delivered into alice's mailbox on this node. We drive the inbound handler directly
	// rather than over a socket.
	raw := []byte("From: ext@gmail.com\r\nTo: alice@" + foldBridgeDomain + "\r\nSubject: hello\r\n\r\nhi alice from the legacy world\r\n")
	if err := f.br.Inbound().HandleMessage(ctx, "1.2.3.4", "ext@gmail.com", []string{"alice@" + foldBridgeDomain}, raw); err != nil {
		t.Fatalf("inbound HandleMessage: %v", err)
	}

	// The bridged message must be in alice's durable mailbox on the shared node.
	aliceRxHex := fmt.Sprintf("%x", f.aliceKP.X25519Public[:])
	count, err := f.n.Relay().Mailbox().Count(ctx, aliceRxHex)
	if err != nil {
		t.Fatalf("mailbox count: %v", err)
	}
	if count != 1 {
		t.Fatalf("alice mailbox count = %d, want 1 (bridged mail not delivered to the shared node)", count)
	}
}

// queueOutbound puts a message from alice to `to` in the bridge's outbound queue, as a STORE of
// an older-format envelope would.
func (f *foldedBridge) queueOutbound(t *testing.T, to string, hash byte) {
	t.Helper()
	msg, err := message.NewPlaintextMessage("alice@"+foldDMCNDomain, to, "Hi", "Hello", f.aliceKP.Ed25519Public)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(f.aliceKP.Ed25519Private); err != nil {
		t.Fatalf("sign: %v", err)
	}
	env, err := message.Encrypt(sm, []message.RecipientInfo{{DeviceID: f.aliceKP.DeviceID, X25519Pub: f.bridgeKP.X25519Public}})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	f.n.Relay().Store().Store(fmt.Sprintf("%x", f.bridgeKP.X25519Public[:]), env, [32]byte{hash})
}

// waitForNotices starts the bridge and waits until its outbound queue is empty and alice's
// mailbox holds want failure notices.
func (f *foldedBridge) waitForNotices(t *testing.T, want int) {
	t.Helper()
	ctx := context.Background()
	if err := f.br.Start(); err != nil {
		t.Fatalf("start bridge: %v", err)
	}
	queue := fmt.Sprintf("%x", f.bridgeKP.X25519Public[:])
	aliceRxHex := fmt.Sprintf("%x", f.aliceKP.X25519Public[:])
	deadline := time.Now().Add(5 * time.Second)
	for {
		count, err := f.n.Relay().Mailbox().Count(ctx, aliceRxHex)
		if err != nil {
			t.Fatalf("mailbox count: %v", err)
		}
		queued := len(f.n.Relay().Store().Queued(queue))
		if count == want && queued == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d envelope(s) still queued, %d notice(s) in alice's mailbox; want 0 and %d", queued, count, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A refusal no retry can change ends the message on the first attempt, with the lifetime nowhere
// near up, and alice gets a failure notice. The message here is addressed to a DMCN address,
// which the bridge will never send as legacy mail.
func TestBridgeFoldDropsOutboundItWillNeverSend(t *testing.T) {
	stub := &bridge.StubSMTPDeliverer{}
	f := newFoldedBridge(t, bridge.Config{PollInterval: 50 * time.Millisecond, OutboundMaxAge: 120 * time.Hour, Deliverer: stub})

	f.queueOutbound(t, "bob@"+foldDMCNDomain, 1)
	f.waitForNotices(t, 1)
	if len(stub.Messages) != 0 {
		t.Fatal("the refused message was delivered")
	}
}

// A refusal a retry could change is retried, but not forever: once the message has waited
// OutboundMaxAge the bridge drops it and alice gets a failure notice. The second message here is
// over alice's hourly limit; the lifetime is a millisecond, so its first attempt is its last.
func TestBridgeFoldGivesUpOnOutboundAfterItsLifetime(t *testing.T) {
	stub := &bridge.StubSMTPDeliverer{}
	f := newFoldedBridge(t, bridge.Config{PollInterval: 50 * time.Millisecond, OutboundMaxAge: time.Millisecond, OutboundRateLimit: 1, Deliverer: stub})

	f.queueOutbound(t, "first@gmail.com", 1)
	f.queueOutbound(t, "second@gmail.com", 2)
	f.waitForNotices(t, 1)
	if len(stub.Messages) != 1 {
		t.Fatalf("expected exactly one delivery, got %d", len(stub.Messages))
	}
}
