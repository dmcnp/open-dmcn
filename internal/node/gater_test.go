package node

import (
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"

	"dmcn.dev/open-dmcn/internal/peerpolicy"
)

type fixedReader []byte

func (d fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = d[i%len(d)]
	}
	return len(p), nil
}

func testPeerID(t *testing.T, seed byte) peer.ID {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed
	}
	priv, _, err := crypto.GenerateEd25519Key(fixedReader(b))
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("derive id: %v", err)
	}
	return id
}

func TestPolicyGaterIntercepts(t *testing.T) {
	allowed := testPeerID(t, 1)
	denied := testPeerID(t, 2)
	g := newPolicyGater(peerpolicy.NewPeerAllowList([]peer.ID{allowed}))

	addr := multiaddr.StringCast("/ip4/127.0.0.1/tcp/1")

	if !g.InterceptPeerDial(allowed) || g.InterceptPeerDial(denied) {
		t.Error("InterceptPeerDial should mirror the policy")
	}
	if !g.InterceptAddrDial(allowed, addr) || g.InterceptAddrDial(denied, addr) {
		t.Error("InterceptAddrDial should mirror the policy")
	}
	if !g.InterceptSecured(network.DirInbound, allowed, nil) || g.InterceptSecured(network.DirInbound, denied, nil) {
		t.Error("InterceptSecured should mirror the policy")
	}
	// InterceptAccept runs pre-handshake without a peer ID and must always allow.
	if !g.InterceptAccept(nil) {
		t.Error("InterceptAccept should always allow (no peer ID yet)")
	}
}

func TestBuildPeerPolicy(t *testing.T) {
	a := testPeerID(t, 1)
	b := testPeerID(t, 2)
	c := testPeerID(t, 3)
	maddr := func(id peer.ID, port int) string {
		return fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", port, id)
	}

	t.Run("empty is deny-by-default", func(t *testing.T) {
		p, err := buildPeerPolicy(Config{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.(peerpolicy.AllowNone); !ok {
			t.Fatalf("got %T, want AllowNone", p)
		}
	})

	t.Run("star is open mode", func(t *testing.T) {
		p, err := buildPeerPolicy(Config{AllowedPeers: []string{"*"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.(peerpolicy.AllowAll); !ok {
			t.Fatalf("got %T, want AllowAll", p)
		}
	})

	t.Run("explicit AllowedPeers only; Peers are NOT auto-trusted", func(t *testing.T) {
		p, err := buildPeerPolicy(Config{
			AllowedPeers: []string{a.String()},                 // bare base58 — the only static trust entry
			Peers:        []string{maddr(b, 10), maddr(c, 11)}, // bootstrap/discovery only, NOT trust
		})
		if err != nil {
			t.Fatal(err)
		}
		if !p.Allow(peerpolicy.PeerContext{ID: a}) {
			t.Errorf("expected explicit allowed peer %s in the allow-set", a)
		}
		// Peers are bootstrap/discovery only — trust comes from a credential presented at
		// /dmcn/join, never from being a configured bootstrap peer.
		for _, id := range []peer.ID{b, c} {
			if p.Allow(peerpolicy.PeerContext{ID: id}) {
				t.Errorf("bootstrap peer %s must NOT be auto-trusted by the static policy", id)
			}
		}
	})

	t.Run("garbage allowed peer errors", func(t *testing.T) {
		if _, err := buildPeerPolicy(Config{AllowedPeers: []string{"not-a-peer"}}); err == nil {
			t.Error("expected error for malformed allowed peer")
		}
	})
}
