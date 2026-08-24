package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
)

// TestFederation proves the reference daemon federates across domains — the protocol's whole point.
// Two serving nodes each host their own domain; alice@a.test (on node A) sends to bob@b.test (on
// node B). Node A must RESOLVE bob's record from B's fleet (DNS-seeded, cross-domain) and STORE to
// B's relay, then bob reads it on B. It exercises the resolver + relay federation on the real daemon
// send/read paths (the in-process router/proxy the webmail uses).
func TestFederation(t *testing.T) {
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx := context.Background()

	dnsStub := func(context.Context, string, string) error { return nil }
	nodeA := mustServingNode(t, ctx, "a.test", dnsStub)
	defer nodeA.Close()
	nodeB := mustServingNode(t, ctx, "b.test", dnsStub)
	defer nodeB.Close()

	// Each domain's authority key + signed DAR, published to its own node.
	rootA, darA := mustDomain(t, ctx, nodeA, "a.test")
	rootB, darB := mustDomain(t, ctx, nodeB, "b.test")

	// Cross-seed static _dmcn so each node can resolve the OTHER domain's fleet (the DNS-seeded
	// federation anchor: fingerprint + a dialable seed).
	crossDNS := map[string]domainverify.Record{
		"a.test": {Fingerprint: darA.Fingerprint(), Seeds: []string{seedAddr(nodeA)}},
		"b.test": {Fingerprint: darB.Fingerprint(), Seeds: []string{seedAddr(nodeB)}},
	}
	nodeA.SetStaticDNS(crossDNS)
	nodeB.SetStaticDNS(crossDNS)

	// Connect A → B and let the join settle.
	if err := nodeA.ConnectPeer(seedAddr(nodeB)); err != nil {
		t.Fatalf("connect A→B: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Provision alice on A and bob on B (browser-equivalent self-signed record → operator routing).
	aliceKP, aliceRec := newSignedRecord(t, "alice@a.test")
	if _, err := provisionIdentity(ctx, nodeA, rootA, "a.test", aliceRec, time.Now()); err != nil {
		t.Fatalf("provision alice: %v", err)
	}
	bobKP, bobRec := newSignedRecord(t, "bob@b.test")
	if _, err := provisionIdentity(ctx, nodeB, rootB, "b.test", bobRec, time.Now()); err != nil {
		t.Fatalf("provision bob: %v", err)
	}
	_ = aliceKP

	// Node A resolves bob's record cross-domain (this is the federation resolve: A dials B's seed).
	resolvedBob, err := nodeA.Lookup(ctx, "bob@b.test")
	if err != nil {
		t.Fatalf("A failed to resolve bob@b.test across the federation: %v", err)
	}
	if len(resolvedBob.RelayHints) == 0 {
		t.Fatal("resolved bob has no relay hints")
	}

	// alice composes a split message to bob and signs the envelope hash.
	const bodyText = "hello across domains"
	env, envHash, sig := composeSplit(t, aliceKP, "alice@a.test", bobKP, resolvedBob, bodyText)

	// STORE cross-domain via A's in-process router → routed to bob's hint (node B, a remote dial).
	router := newInProcRouter(nodeA)
	if err := router.ConnectPeer(resolvedBob.RelayHints[0]); err != nil {
		t.Fatalf("A connect to bob's relay (B): %v", err)
	}
	storedHash, err := router.StorePreSignedOnPeer(ctx, resolvedBob.RelayHints[0], "alice@a.test", sig, env)
	if err != nil {
		t.Fatalf("cross-domain STORE A→B: %v", err)
	}
	if storedHash != envHash {
		t.Fatalf("stored hash mismatch")
	}

	// bob reads his mailbox on node B and the message decrypts to the original plaintext.
	proxy := newInProcRelay(nodeB, func(ctx context.Context, a string) (*identity.IdentityRecord, error) {
		return nodeB.Lookup(ctx, a)
	})
	nonce, err := proxy.Challenge(ctx, "bob@b.test")
	if err != nil {
		t.Fatalf("challenge on B: %v", err)
	}
	bobSig, err := crypto.Sign(bobKP.Ed25519Private, nonce)
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := proxy.List(ctx, "bob@b.test", nonce, bobSig, 0, nil)
	if err != nil {
		t.Fatalf("list on B: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("bob's mailbox on B has %d messages, want 1", len(entries))
	}

	hdr, err := message.DecryptHeader(env, bobKP.X25519Private, bobKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt header: %v", err)
	}
	dc, err := message.DecryptBody(env, &hdr.Header, bobKP.X25519Private, bobKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	if string(dc.Body.Content) != bodyText {
		t.Fatalf("decrypted body = %q, want %q", dc.Body.Content, bodyText)
	}
}

// --- shared federation test helpers ---

func mustServingNode(t *testing.T, ctx context.Context, domain string, dns func(context.Context, string, string) error) *node.Node {
	t.Helper()
	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       domain,
		DNSVerifier:  dns,
	})
	if err != nil {
		t.Fatalf("node.New(%s): %v", domain, err)
	}
	return n
}

// mustDomain generates the domain authority key, signs its DAR, and publishes it to the node.
func mustDomain(t *testing.T, ctx context.Context, n *node.Node, domain string) (*identity.IdentityKeyPair, *identity.DomainAuthorityRecord) {
	t.Helper()
	root, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dar, err := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	if _, err := n.PublishDAR(ctx, dar); err != nil {
		t.Fatalf("publish DAR %s: %v", domain, err)
	}
	return root, dar
}

func seedAddr(n *node.Node) string {
	return fmt.Sprintf("%s/p2p/%s", n.Addrs()[0], n.PeerID())
}

// newSignedRecord builds a browser-equivalent self-signed IdentityRecord (no operator credential).
func newSignedRecord(t *testing.T, address string) (*identity.IdentityKeyPair, *identity.IdentityRecord) {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	return kp, rec
}

// composeSplit builds a split envelope from sender→recipient, returning it plus its hash and the
// sender's signature over that hash (the exact bytes the browser signs for a STORE).
func composeSplit(t *testing.T, senderKP *identity.IdentityKeyPair, senderAddr string, recipientKP *identity.IdentityKeyPair, recipientRec *identity.IdentityRecord, body string) (*message.EncryptedEnvelope, [32]byte, []byte) {
	t.Helper()
	pt, err := message.NewPlaintextMessage(senderAddr, recipientRec.Address, "Hi", body, senderKP.Ed25519Public)
	if err != nil {
		t.Fatal(err)
	}
	sh, content, err := message.Split(pt, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	env, err := message.EncryptSplit(sh, content,
		[]message.RecipientInfo{{DeviceID: recipientKP.DeviceID, X25519Pub: recipientRec.X25519Public}},
		senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	envBytes, err := proto.Marshal(env.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	envHash := crypto.SHA256Hash(envBytes)
	sig, err := crypto.Sign(senderKP.Ed25519Private, envHash[:])
	if err != nil {
		t.Fatal(err)
	}
	return env, envHash, sig
}
