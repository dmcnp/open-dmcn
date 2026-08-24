package relay

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/core/onion"
	"dmcn.dev/open-dmcn/internal/registry"
)

func connectHosts(t *testing.T, ctx context.Context, a, b host.Host) {
	t.Helper()
	if err := a.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

// buildStoreRequest creates a signed split envelope from sender to recipient and
// the StoreRequest carrying it. Returns the request and the recipient's storage
// key (X25519 hex).
func buildStoreRequest(t *testing.T, senderAddr string, senderKP, recipientKP *identity.IdentityKeyPair) (*dmcnpb.StoreRequest, string) {
	t.Helper()
	msg, err := message.NewPlaintextMessage(senderAddr, "recipient@dmcn.localhost", "Subj", "onion body", senderKP.Ed25519Public)
	if err != nil {
		t.Fatal(err)
	}
	sh, content, err := message.Split(msg, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{X25519Pub: recipientKP.X25519Public}}, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	envProto := env.ToProto()
	envBytes, err := proto.Marshal(envProto)
	if err != nil {
		t.Fatal(err)
	}
	envHash := crypto.SHA256Hash(envBytes)
	sig, err := crypto.Sign(senderKP.Ed25519Private, envHash[:])
	if err != nil {
		t.Fatal(err)
	}
	return &dmcnpb.StoreRequest{SenderAddress: senderAddr, SenderSignature: sig, Envelope: envProto},
		fmt.Sprintf("%x", recipientKP.X25519Public[:])
}

// buildDeliveryStore wraps buildStoreRequest as the marshaled delivery payload an
// onion exit hop carries.
func buildDeliveryStore(t *testing.T, senderAddr string, senderKP, recipientKP *identity.IdentityKeyPair) ([]byte, string) {
	t.Helper()
	sr, hex := buildStoreRequest(t, senderAddr, senderKP, recipientKP)
	deliveryBytes, err := proto.Marshal(sr)
	if err != nil {
		t.Fatal(err)
	}
	return deliveryBytes, hex
}

// senderLookup returns a LookupFunc resolving senderAddr to senderKP's record.
func senderLookup(senderAddr string, senderKP *identity.IdentityKeyPair) func(context.Context, string) (*identity.IdentityRecord, error) {
	rec := &identity.IdentityRecord{Address: senderAddr, Ed25519Public: senderKP.Ed25519Public, X25519Public: senderKP.X25519Public}
	return func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == senderAddr {
			return rec, nil
		}
		return nil, registry.ErrNotFound
	}
}

func TestHandleOnionDisabled(t *testing.T) {
	h := newTestHost(t)
	defer h.Close()
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) { return nil, registry.ErrNotFound }
	r := New(h, lookup) // no WithOnionKey ⇒ forwarding disabled

	resp := r.handleOnion(h.ID(), &dmcnpb.OnionForwardRequest{Packet: &dmcnpb.OnionPacket{}})
	if e := resp.GetError(); e == nil || e.Code != "ONION_DISABLED" {
		t.Fatalf("expected ONION_DISABLED, got %v", resp)
	}
}

func TestHandleOnionExpired(t *testing.T) {
	h := newTestHost(t)
	defer h.Close()
	pub, priv, _ := crypto.GenerateX25519KeyPair()
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) { return nil, registry.ErrNotFound }
	r := New(h, lookup, WithOnionKey(priv))

	// Single-hop DELIVER onion to this relay, expired an hour ago.
	pkt, err := onion.BuildOnion(
		[]onion.Hop{{PeerID: h.ID().String(), X25519Pub: pub}},
		[]byte("ignored"),
		time.Now().Add(-time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp := r.handleOnion(h.ID(), &dmcnpb.OnionForwardRequest{Packet: pkt})
	if e := resp.GetError(); e == nil || e.Code != "ONION_EXPIRED" {
		t.Fatalf("expected ONION_EXPIRED, got %v", resp)
	}
}

// A duplicate onion packet is ACKed but processed only once (idempotent), so a
// retried/replayed packet does not double-deliver.
func TestHandleOnionDedup(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const senderAddr = "sender@dmcn.localhost"

	h := newTestHost(t)
	defer h.Close()
	pub, priv, _ := crypto.GenerateX25519KeyPair()
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == senderAddr {
			return &identity.IdentityRecord{Address: senderAddr, Ed25519Public: senderKP.Ed25519Public, X25519Public: senderKP.X25519Public}, nil
		}
		return nil, registry.ErrNotFound
	}
	r := New(h, lookup, WithOnionKey(priv))

	delivery, recipientHex := buildDeliveryStore(t, senderAddr, senderKP, recipientKP)
	pkt, err := onion.BuildOnion([]onion.Hop{{PeerID: h.ID().String(), X25519Pub: pub}}, delivery, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		resp := r.handleOnion(h.ID(), &dmcnpb.OnionForwardRequest{Packet: pkt})
		if of := resp.GetOnionForward(); of == nil || !of.Accepted {
			t.Fatalf("call %d: expected accepted ACK, got %v", i, resp)
		}
	}
	if envs, _ := r.Store().Fetch(recipientHex); len(envs) != 1 {
		t.Fatalf("duplicate packet must deliver once, got %d", len(envs))
	}
}

// Per-hop timing jitter does not break delivery (and exercises the jitter path).
func TestHandleOnionWithJitter(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const senderAddr = "sender@dmcn.localhost"

	h := newTestHost(t)
	defer h.Close()
	pub, priv, _ := crypto.GenerateX25519KeyPair()
	r := New(h, senderLookup(senderAddr, senderKP), WithOnionKey(priv), WithOnionJitter(5*time.Millisecond))

	delivery, recipientHex := buildDeliveryStore(t, senderAddr, senderKP, recipientKP)
	pkt, err := onion.BuildOnion([]onion.Hop{{PeerID: h.ID().String(), X25519Pub: pub}}, delivery, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resp := r.handleOnion(h.ID(), &dmcnpb.OnionForwardRequest{Packet: pkt}); resp.GetOnionForward() == nil || !resp.GetOnionForward().Accepted {
		t.Fatalf("jittered delivery should still be accepted, got %v", resp)
	}
	if envs, _ := r.Store().Fetch(recipientHex); len(envs) != 1 {
		t.Fatalf("expected 1 delivered envelope, got %d", len(envs))
	}
}

// TestOnionThreeHopDelivery is the B2 proof-of-concept: a 3-relay onion
// (entry → middle → exit) delivers a split envelope into the exit's store, and
// no intermediate relay sees the delivery — the core onion-routing property.
func TestOnionThreeHopDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const senderAddr = "sender@dmcn.localhost"

	// Hosts: sender + 3 relays, connected in a line sender→entry→middle→exit.
	senderH := newTestHost(t)
	entryH := newTestHost(t)
	middleH := newTestHost(t)
	exitH := newTestHost(t)
	for _, h := range []host.Host{senderH, entryH, middleH, exitH} {
		defer h.Close()
	}
	connectHosts(t, ctx, senderH, entryH)
	connectHosts(t, ctx, entryH, middleH)
	connectHosts(t, ctx, middleH, exitH)

	// Onion keys per relay.
	entryPub, entryPriv, _ := crypto.GenerateX25519KeyPair()
	middlePub, middlePriv, _ := crypto.GenerateX25519KeyPair()
	exitPub, exitPriv, _ := crypto.GenerateX25519KeyPair()

	stub := func(context.Context, string) (*identity.IdentityRecord, error) { return nil, registry.ErrNotFound }
	// Only the exit performs final delivery, so only it must resolve the sender.
	exitLookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == senderAddr {
			return &identity.IdentityRecord{Address: senderAddr, Ed25519Public: senderKP.Ed25519Public, X25519Public: senderKP.X25519Public}, nil
		}
		return nil, registry.ErrNotFound
	}

	entry := New(entryH, stub, WithOnionKey(entryPriv))
	middle := New(middleH, stub, WithOnionKey(middlePriv))
	exit := New(exitH, exitLookup, WithOnionKey(exitPriv))
	for _, r := range []*Relay{entry, middle, exit} {
		r.Start()
	}
	sender := New(senderH, stub) // sends only; no handlers needed

	delivery, recipientHex := buildDeliveryStore(t, senderAddr, senderKP, recipientKP)
	route := []onion.Hop{
		{PeerID: entryH.ID().String(), X25519Pub: entryPub},
		{PeerID: middleH.ID().String(), X25519Pub: middlePub},
		{PeerID: exitH.ID().String(), X25519Pub: exitPub},
	}
	pkt, err := onion.BuildOnion(route, delivery, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// The whole chain resolves synchronously: by the time the entry ACKs, the exit
	// has delivered.
	if err := sender.ClientOnionForward(ctx, entryH.ID(), pkt); err != nil {
		t.Fatalf("onion forward: %v", err)
	}

	envs, _ := exit.Store().Fetch(recipientHex)
	if len(envs) != 1 {
		t.Fatalf("exit relay should hold exactly 1 delivered envelope, got %d", len(envs))
	}
	if !envs[0].IsSplit() {
		t.Fatal("delivered envelope must be split (v2)")
	}
	// Intermediaries only forwarded — they must not have stored the delivery.
	if got, _ := entry.Store().Fetch(recipientHex); len(got) != 0 {
		t.Fatalf("entry relay must not store the delivery, got %d", len(got))
	}
	if got, _ := middle.Store().Fetch(recipientHex); len(got) != 0 {
		t.Fatalf("middle relay must not store the delivery, got %d", len(got))
	}

	// The recipient can decrypt what the exit stored — end-to-end through onion.
	sh, err := message.DecryptHeader(envs[0], recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("recipient decrypt header: %v", err)
	}
	content, err := message.DecryptBody(envs[0], &sh.Header, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("recipient decrypt body: %v", err)
	}
	if string(content.Body.Content) != "onion body" {
		t.Fatalf("body mismatch: %q", content.Body.Content)
	}
}
