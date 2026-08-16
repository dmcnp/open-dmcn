package relay

import (
	"context"
	"fmt"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/peerpolicy"
)

func newTestHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create test host: %v", err)
	}
	return h
}

func TestMessageStoreBasic(t *testing.T) {
	store := NewMessageStore()

	kp, _ := identity.GenerateIdentityKeyPair()
	msg, _ := message.NewPlaintextMessage(
		"alice@localhost", "bob@localhost", "Test", "Hello",
		kp.Ed25519Public,
	)
	sm := &message.SignedMessage{Plaintext: *msg}
	sm.Sign(kp.Ed25519Private)

	recipKP, _ := identity.GenerateIdentityKeyPair()
	env, _ := message.Encrypt(sm, []message.RecipientInfo{{
		DeviceID: recipKP.DeviceID, X25519Pub: recipKP.X25519Public,
	}})

	hash := [32]byte{1, 2, 3}
	store.Store("bob@localhost", env, hash)

	// Count
	if c := store.Count(); c != 1 {
		t.Errorf("count = %d, want 1", c)
	}

	// Fetch
	envs, hashes := store.Fetch("bob@localhost")
	if len(envs) != 1 {
		t.Fatalf("fetched %d, want 1", len(envs))
	}
	if hashes[0] != hash {
		t.Error("hash mismatch")
	}

	// Delivery status
	status, err := store.DeliveryStatusOf(hash)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status != Pending {
		t.Errorf("status = %d, want Pending", status)
	}

	// Ack
	if err := store.Ack(hash); err != nil {
		t.Fatalf("ack: %v", err)
	}

	status, _ = store.DeliveryStatusOf(hash)
	if status != Delivered {
		t.Errorf("status after ack = %d, want Delivered", status)
	}

	// Fetch should return empty after ack (only pending)
	envs, _ = store.Fetch("bob@localhost")
	if len(envs) != 0 {
		t.Errorf("fetched %d after ack, want 0", len(envs))
	}
}

func TestMessageStoreNotFound(t *testing.T) {
	store := NewMessageStore()

	// Ack non-existent
	err := store.Ack([32]byte{99})
	if err != ErrEnvelopeNotFound {
		t.Errorf("ack non-existent: got %v, want ErrEnvelopeNotFound", err)
	}

	// Status non-existent
	_, err = store.DeliveryStatusOf([32]byte{99})
	if err != ErrEnvelopeNotFound {
		t.Errorf("status non-existent: got %v, want ErrEnvelopeNotFound", err)
	}
}

func TestMessageStoreMultiple(t *testing.T) {
	store := NewMessageStore()

	kp, _ := identity.GenerateIdentityKeyPair()
	recipKP, _ := identity.GenerateIdentityKeyPair()

	for i := 0; i < 5; i++ {
		msg, _ := message.NewPlaintextMessage(
			"alice@localhost", "bob@localhost", "", "msg",
			kp.Ed25519Public,
		)
		sm := &message.SignedMessage{Plaintext: *msg}
		sm.Sign(kp.Ed25519Private)
		env, _ := message.Encrypt(sm, []message.RecipientInfo{{
			DeviceID: recipKP.DeviceID, X25519Pub: recipKP.X25519Public,
		}})

		hash := [32]byte{byte(i)}
		store.Store("bob@localhost", env, hash)
	}

	if c := store.Count(); c != 5 {
		t.Errorf("count = %d, want 5", c)
	}

	envs, _ := store.Fetch("bob@localhost")
	if len(envs) != 5 {
		t.Errorf("fetched %d, want 5", len(envs))
	}

	// Fetch for different address returns empty
	envs, _ = store.Fetch("charlie@localhost")
	if len(envs) != 0 {
		t.Errorf("fetched %d for charlie, want 0", len(envs))
	}
}

func TestRateLimiterBasic(t *testing.T) {
	rl := NewRateLimiter(3)

	// First 3 should be allowed
	for i := 0; i < 3; i++ {
		if !rl.Allow("alice@localhost") {
			t.Errorf("attempt %d should be allowed", i)
		}
	}

	// 4th should be denied
	if rl.Allow("alice@localhost") {
		t.Error("4th attempt should be denied")
	}

	// Different sender should be allowed
	if !rl.Allow("bob@localhost") {
		t.Error("bob should be allowed (separate limit)")
	}
}

func TestRateLimiterExpiry(t *testing.T) {
	rl := NewRateLimiter(2)

	// Manually set timestamps in the past
	past := time.Now().Add(-2 * time.Hour)
	rl.timestamps["alice@localhost"] = []time.Time{past, past}

	// Should be allowed since old timestamps are pruned
	if !rl.Allow("alice@localhost") {
		t.Error("should be allowed after expiry")
	}
}

func TestPeersHandlerAndClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h1 := newTestHost(t)
	defer h1.Close()
	h2 := newTestHost(t)
	defer h2.Close()

	// Connect hosts
	h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), time.Hour)
	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) {
		return nil, fmt.Errorf("not found")
	}

	expectedPeers := []string{"/ip4/1.2.3.4/tcp/7400/p2p/QmTest1", "/ip4/5.6.7.8/tcp/7400/p2p/QmTest2"}

	r1 := New(h1, lookup, WithPeers(expectedPeers))
	r1.Start()
	defer r1.Stop()

	r2 := New(h2, lookup)

	// Query peers
	peers, err := r2.ClientPeers(ctx, h1.ID())
	if err != nil {
		t.Fatalf("ClientPeers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(peers))
	}
	if peers[0] != expectedPeers[0] || peers[1] != expectedPeers[1] {
		t.Errorf("peers = %v, want %v", peers, expectedPeers)
	}
}

// TestPeerPolicyGatesStreams verifies the relay-level peer gate (defense-in-
// depth, independent of the connection gater): a non-allowlisted peer that
// reaches the relay gets its relay and peer-discovery streams dropped.
func TestPeerPolicyGatesStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h1 := newTestHost(t) // the relay (plain host, no gater)
	defer h1.Close()
	h2 := newTestHost(t) // a disallowed caller
	defer h2.Close()

	h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), time.Hour)
	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) {
		return nil, fmt.Errorf("not found")
	}

	// h1's relay allowlists only itself, so h2 is not federated.
	r1 := New(h1, lookup,
		WithPeers([]string{"/ip4/1.2.3.4/tcp/7400/p2p/QmTest1"}),
		WithPeerPolicy(peerpolicy.NewPeerAllowList([]peer.ID{h1.ID()})),
	)
	r1.Start()
	defer r1.Stop()

	r2 := New(h2, lookup)

	// PING is an open health check — NOT connection-gated — so it succeeds even from a
	// non-federated peer (per-op model: only credential-bearing / no-message-credential ops are
	// gated; STORE/FETCH self-authenticate via the message).
	if _, err := r2.ClientPing(ctx, h1.ID()); err != nil {
		t.Errorf("PING is open and should succeed even unfederated: %v", err)
	}
	// Peer discovery IS gated to federated peers — a non-allowlisted caller is dropped.
	if _, err := r2.ClientPeers(ctx, h1.ID()); err == nil {
		t.Error("peer discovery from a non-federated peer should be dropped")
	}
}

// TestPeerPolicyAllowsFederatedPeer is the positive control: an allowlisted
// peer is served normally.
func TestPeerPolicyAllowsFederatedPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h1 := newTestHost(t)
	defer h1.Close()
	h2 := newTestHost(t)
	defer h2.Close()

	h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), time.Hour)
	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) {
		return nil, fmt.Errorf("not found")
	}

	// Allowlist h2 so it is federated.
	r1 := New(h1, lookup, WithPeerPolicy(peerpolicy.NewPeerAllowList([]peer.ID{h2.ID()})))
	r1.Start()
	defer r1.Stop()

	r2 := New(h2, lookup)
	// A federated (allowlisted) peer is served the gated peer-discovery stream.
	if _, err := r2.ClientPeers(ctx, h1.ID()); err != nil {
		t.Errorf("peer discovery from a federated peer should succeed: %v", err)
	}
}

func TestPeersHandlerEmptyList(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h1 := newTestHost(t)
	defer h1.Close()
	h2 := newTestHost(t)
	defer h2.Close()

	h2.Peerstore().AddAddrs(h1.ID(), h1.Addrs(), time.Hour)
	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) {
		return nil, fmt.Errorf("not found")
	}

	// No peers configured
	r1 := New(h1, lookup)
	r1.Start()
	defer r1.Stop()

	r2 := New(h2, lookup)

	peers, err := r2.ClientPeers(ctx, h1.ID())
	if err != nil {
		t.Fatalf("ClientPeers: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("got %d peers, want 0", len(peers))
	}
}

func TestPeersAccessor(t *testing.T) {
	h := newTestHost(t)
	defer h.Close()

	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) {
		return nil, fmt.Errorf("not found")
	}

	peers := []string{"/ip4/1.2.3.4/tcp/7400/p2p/QmTest"}
	r := New(h, lookup, WithPeers(peers))
	got := r.Peers()
	if len(got) != 1 || got[0] != peers[0] {
		t.Errorf("Peers() = %v, want %v", got, peers)
	}
}

func TestRateLimiterWindow(t *testing.T) {
	rl := NewRateLimiter(2)

	// Override nowFunc to control time
	now := time.Now()
	rl.nowFunc = func() time.Time { return now }

	rl.Allow("alice@localhost")
	rl.Allow("alice@localhost")

	// At current time, 3rd should be denied
	if rl.Allow("alice@localhost") {
		t.Error("3rd should be denied within window")
	}

	// Move time forward past the window
	rl.nowFunc = func() time.Time { return now.Add(61 * time.Minute) }

	// Should be allowed now
	if !rl.Allow("alice@localhost") {
		t.Error("should be allowed after window expires")
	}
}
