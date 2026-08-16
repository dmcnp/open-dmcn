package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
)

// TestDaemonInProcessRoundTrip exercises the daemon's in-process wiring end-to-end without a
// browser or a second node: it seeds a domain + two identities on one serving node, then drives
// the SAME adapters the webmail handlers use — inProcRouter (STORE) and inProcRelay (challenge /
// list / body / delete) — to send alice→bob, read the message, and delete it. This is the P1
// gate: it proves the fold (webmail backend sharing the node in-process, no self-dial) and the
// zero-knowledge auth (each mailbox op authorized by a signature over a server-issued nonce).
func TestDaemonInProcessRoundTrip(t *testing.T) {
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx := context.Background()
	const domain = "localhost"

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       domain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.Close()

	// Seed the domain + alice + bob (mirrors what main() does at boot).
	seeds := newSeedStore(t.TempDir(), "test-pass")
	now := time.Now()
	rootKP, err := seeds.seedDomain(ctx, n, domain, now)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	aliceKP, err := seeds.seedIdentity(ctx, n, rootKP, "alice@"+domain, now)
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	bobKP, err := seeds.seedIdentity(ctx, n, rootKP, "bob@"+domain, now)
	if err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) {
		return n.Lookup(ctx, addr)
	}

	// Bob's record must resolve with operator-owned relay hints (so a sender can route to him).
	bobRec, err := n.Lookup(ctx, "bob@"+domain)
	if err != nil {
		t.Fatalf("lookup bob: %v", err)
	}
	if len(bobRec.RelayHints) == 0 {
		t.Fatal("bob resolved with no relay hints")
	}

	// Alice composes a split (durable-mailbox) message to bob and signs the envelope hash — the
	// exact bytes the browser signs for a STORE.
	const bodyText = "hi bob, this is alice"
	pt, err := message.NewPlaintextMessage("alice@"+domain, "bob@"+domain, "Hello", bodyText, aliceKP.Ed25519Public)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	sh, content, err := message.Split(pt, aliceKP.Ed25519Private)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	env, err := message.EncryptSplit(sh, content,
		[]message.RecipientInfo{{DeviceID: bobKP.DeviceID, X25519Pub: bobRec.X25519Public}},
		aliceKP.Ed25519Private)
	if err != nil {
		t.Fatalf("encrypt split: %v", err)
	}
	if !env.IsSplit() {
		t.Fatal("expected a split envelope for durable mailbox storage")
	}
	envBytes, err := proto.Marshal(env.ToProto())
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	envHash := crypto.SHA256Hash(envBytes)
	senderSig, err := crypto.Sign(aliceKP.Ed25519Private, envHash[:])
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}

	// STORE via the in-process router, routed to bob's own relay hint (this node).
	router := newInProcRouter(n)
	if err := router.ConnectPeer(bobRec.RelayHints[0]); err != nil {
		t.Fatalf("connect to bob's hint: %v", err)
	}
	storedHash, err := router.StorePreSignedOnPeer(ctx, bobRec.RelayHints[0], "alice@"+domain, senderSig, env)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if storedHash != envHash {
		t.Fatalf("stored hash %x != envelope hash %x", storedHash, envHash)
	}

	// Bob reads his mailbox via the in-process relay proxy. Each op: challenge → sign nonce → run.
	proxy := newInProcRelay(n, lookup)
	bobSign := func(nonce []byte) []byte {
		s, serr := crypto.Sign(bobKP.Ed25519Private, nonce)
		if serr != nil {
			t.Fatalf("bob sign: %v", serr)
		}
		return s
	}

	// LIST: one entry, hash matches.
	nonce, err := proxy.Challenge(ctx, "bob@"+domain)
	if err != nil {
		t.Fatalf("challenge (list): %v", err)
	}
	entries, _, err := proxy.List(ctx, "bob@"+domain, nonce, bobSign(nonce), 0, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	var entryHash [32]byte
	copy(entryHash[:], entries[0].Hash)
	if entryHash != envHash {
		t.Fatalf("entry hash %x != envelope hash %x", entryHash, envHash)
	}

	// BODY: retrieved body bytes are byte-identical, and the message decrypts to bob.
	nonceB, err := proxy.Challenge(ctx, "bob@"+domain)
	if err != nil {
		t.Fatalf("challenge (body): %v", err)
	}
	body, err := proxy.Body(ctx, "bob@"+domain, nonceB, bobSign(nonceB), entryHash)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if !bytes.Equal(body.EncryptedBody, env.EncryptedBody) {
		t.Fatal("retrieved body bytes differ from stored")
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

	// AUTH: a signature from the wrong key (alice signing bob's nonce) must be rejected.
	nonceX, err := proxy.Challenge(ctx, "bob@"+domain)
	if err != nil {
		t.Fatalf("challenge (auth): %v", err)
	}
	wrongSig, _ := crypto.Sign(aliceKP.Ed25519Private, nonceX)
	if _, _, err := proxy.List(ctx, "bob@"+domain, nonceX, wrongSig, 0, nil); err == nil {
		t.Fatal("list accepted a signature from the wrong key")
	}

	// DELETE: then LIST shows an empty mailbox.
	nonceD, err := proxy.Challenge(ctx, "bob@"+domain)
	if err != nil {
		t.Fatalf("challenge (delete): %v", err)
	}
	if err := proxy.Delete(ctx, "bob@"+domain, nonceD, bobSign(nonceD), entryHash); err != nil {
		t.Fatalf("delete: %v", err)
	}
	nonceL, err := proxy.Challenge(ctx, "bob@"+domain)
	if err != nil {
		t.Fatalf("challenge (list2): %v", err)
	}
	entries2, _, err := proxy.List(ctx, "bob@"+domain, nonceL, bobSign(nonceL), 0, nil)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(entries2) != 0 {
		t.Fatalf("want 0 entries after delete, got %d", len(entries2))
	}
}
