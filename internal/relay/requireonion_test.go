package relay

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/onion"
	"dmcn.dev/open-dmcn/dmcnpb"
)

// A direct STORE to a mailbox known to require onion delivery is rejected; the
// same store to a non-onion mailbox is accepted.
func TestRequireOnionRejectsDirectStore(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const senderAddr = "sender@dmcn.localhost"

	h := newTestHost(t)
	defer h.Close()
	r := New(h, senderLookup(senderAddr, senderKP))

	sr, recipientHex := buildStoreRequest(t, senderAddr, senderKP, recipientKP)

	// Recipient requires onion ⇒ direct STORE rejected.
	r.onionRequired.Store(recipientHex, true)
	if e := r.handleStore(h.ID(), sr).GetError(); e == nil || e.Code != "ONION_REQUIRED" {
		t.Fatalf("expected ONION_REQUIRED for direct store, got %v", e)
	}

	// Same recipient without the requirement ⇒ accepted.
	r.onionRequired.Store(recipientHex, false)
	if resp := r.handleStore(h.ID(), sr); resp.GetError() != nil {
		t.Fatalf("non-onion recipient should accept direct store, got %v", resp.GetError())
	}
}

// On the onion path, RequireOnion is satisfied only when the predecessor is a
// relay (genuine mesh delivery); a 1-hop self-delivery from a client is rejected.
func TestRequireOnionOnionArrival(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const senderAddr = "sender@dmcn.localhost"

	h := newTestHost(t)
	defer h.Close()
	exitPub, exitPriv, _ := crypto.GenerateX25519KeyPair()
	r := New(h, senderLookup(senderAddr, senderKP), WithOnionKey(exitPriv))

	delivery, recipientHex := buildDeliveryStore(t, senderAddr, senderKP, recipientKP)
	r.onionRequired.Store(recipientHex, true)

	build := func(t *testing.T) *dmcnpb.OnionPacket {
		pkt, err := onion.BuildOnion([]onion.Hop{{PeerID: h.ID().String(), X25519Pub: exitPub}}, delivery, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}

	pred := newTestHost(t)
	defer pred.Close()

	// Predecessor is a relay ⇒ accepted.
	r.isRelayPeer = func(peer.ID) bool { return true }
	if resp := r.handleOnion(pred.ID(), &dmcnpb.OnionForwardRequest{Packet: build(t)}); resp.GetOnionForward() == nil || !resp.GetOnionForward().Accepted {
		t.Fatalf("mesh delivery to onion-required mailbox should be accepted, got %v", resp)
	}
	if envs, _ := r.Store().Fetch(recipientHex); len(envs) != 1 {
		t.Fatalf("expected 1 delivered envelope, got %d", len(envs))
	}

	// Predecessor is a client (1-hop self-delivery) ⇒ rejected. Use a fresh relay
	// so the dedup cache + store don't mask the result.
	h2 := newTestHost(t)
	defer h2.Close()
	r2 := New(h2, senderLookup(senderAddr, senderKP), WithOnionKey(exitPriv))
	r2.onionRequired.Store(recipientHex, true)
	r2.isRelayPeer = func(peer.ID) bool { return false }
	pkt2, err := onion.BuildOnion([]onion.Hop{{PeerID: h2.ID().String(), X25519Pub: exitPub}}, delivery, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if e := r2.handleOnion(pred.ID(), &dmcnpb.OnionForwardRequest{Packet: pkt2}).GetError(); e == nil || e.Code != "ONION_REQUIRED" {
		t.Fatalf("client-origin 1-hop delivery to onion-required mailbox should be rejected, got %v", e)
	}
	if envs, _ := r2.Store().Fetch(recipientHex); len(envs) != 0 {
		t.Fatalf("rejected delivery must not be stored, got %d", len(envs))
	}
}

// The relay learns a mailbox's RequireOnion policy when the recipient FETCHes
// (its record is authentic and the key is proven), so it can later reject direct
// STOREs without any per-message hint.
func TestFetchLearnsRequireOnion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const recipAddr = "alice@dmcn.localhost"
	recipRec := &identity.IdentityRecord{
		Address:       recipAddr,
		Ed25519Public: recipientKP.Ed25519Public,
		X25519Public:  recipientKP.X25519Public,
		RequireOnion:  true,
	}
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == recipAddr {
			return recipRec, nil
		}
		return nil, fmt.Errorf("unknown")
	}

	relayH := newTestHost(t)
	defer relayH.Close()
	r := New(relayH, lookup)
	r.Start()

	clientH := newTestHost(t)
	defer clientH.Close()
	if err := clientH.Connect(ctx, peer.AddrInfo{ID: relayH.ID(), Addrs: relayH.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	client := New(clientH, lookup)

	if _, _, err := client.ClientFetch(ctx, relayH.ID(), recipientKP, recipAddr); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	recipientHex := fmt.Sprintf("%x", recipientKP.X25519Public[:])
	if !r.requiresOnion(recipientHex) {
		t.Fatal("relay should have learned RequireOnion from the FETCH")
	}
}

// When the record's own flag is off but the effective onion policy (e.g. a domain
// DAR mandate) is on, the relay still learns to require onion.
func TestFetchLearnsOnionFromPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const recipAddr = "alice@onion.me"
	recipRec := &identity.IdentityRecord{
		Address:       recipAddr,
		Ed25519Public: recipientKP.Ed25519Public,
		X25519Public:  recipientKP.X25519Public,
		RequireOnion:  false, // mailbox flag off; the domain policy mandates onion
	}
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == recipAddr {
			return recipRec, nil
		}
		return nil, fmt.Errorf("unknown")
	}

	relayH := newTestHost(t)
	defer relayH.Close()
	// Inject a policy that mandates onion for this domain (simulating a DAR).
	r := New(relayH, lookup, WithOnionPolicy(func(_ context.Context, rec *identity.IdentityRecord) bool {
		return rec.RequireOnion || rec.Address == recipAddr
	}))
	r.Start()

	clientH := newTestHost(t)
	defer clientH.Close()
	if err := clientH.Connect(ctx, peer.AddrInfo{ID: relayH.ID(), Addrs: relayH.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	client := New(clientH, lookup)
	if _, _, err := client.ClientFetch(ctx, relayH.ID(), recipientKP, recipAddr); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if !r.requiresOnion(fmt.Sprintf("%x", recipientKP.X25519Public[:])) {
		t.Fatal("relay should require onion from the domain policy even when the mailbox flag is off")
	}
}
