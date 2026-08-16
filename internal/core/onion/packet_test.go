package onion

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"
)

func hop(t *testing.T) (Hop, [32]byte) {
	t.Helper()
	pub, priv := mustKeyPair(t)
	return Hop{PeerID: fmt.Sprintf("peer-%x", pub[:6]), X25519Pub: pub}, priv
}

// A 3-hop onion peels correctly at each hop: entry → middle (names exit) → exit
// (DELIVER with payload). Each hop only sees the next hop, not the whole route.
func TestBuildPeelThreeHops(t *testing.T) {
	entry, entryPriv := hop(t)
	middle, middlePriv := hop(t)
	exit, exitPriv := hop(t)
	delivery := []byte("marshaled StoreRequest bytes")
	ttl := time.Unix(1700000000, 0)

	pkt, err := BuildOnion([]Hop{entry, middle, exit}, delivery, ttl)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Hop 1 (entry): forwards to middle.
	l1, err := PeelOnion(entryPriv, pkt)
	if err != nil {
		t.Fatalf("peel entry: %v", err)
	}
	if l1.NextHop != middle.PeerID {
		t.Fatalf("entry next_hop = %q, want %q", l1.NextHop, middle.PeerID)
	}
	if l1.Inner == nil || len(l1.Delivery) != 0 {
		t.Fatal("entry layer must carry inner packet, not delivery")
	}
	if l1.TtlUnix != ttl.Unix() {
		t.Fatalf("ttl not carried: %d", l1.TtlUnix)
	}

	// Hop 2 (middle): forwards to exit.
	l2, err := PeelOnion(middlePriv, l1.Inner)
	if err != nil {
		t.Fatalf("peel middle: %v", err)
	}
	if l2.NextHop != exit.PeerID {
		t.Fatalf("middle next_hop = %q, want %q", l2.NextHop, exit.PeerID)
	}

	// Hop 3 (exit): DELIVER.
	l3, err := PeelOnion(exitPriv, l2.Inner)
	if err != nil {
		t.Fatalf("peel exit: %v", err)
	}
	if l3.NextHop != DeliverHop {
		t.Fatalf("exit next_hop = %q, want DELIVER", l3.NextHop)
	}
	if !bytes.Equal(l3.Delivery, delivery) {
		t.Fatalf("delivery payload mismatch: %q", l3.Delivery)
	}
	if l3.Inner != nil {
		t.Fatal("exit layer must not carry an inner packet")
	}
}

// A relay cannot peel a layer that was not sealed to it.
func TestPeelWrongHopFails(t *testing.T) {
	entry, _ := hop(t)
	exit, _ := hop(t)
	_, wrongPriv := mustKeyPair(t)
	pkt, err := BuildOnion([]Hop{entry, exit}, []byte("x"), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PeelOnion(wrongPriv, pkt); err == nil {
		t.Fatal("peeling with a non-route key must fail")
	}
}

func TestBuildOnionEmptyRoute(t *testing.T) {
	if _, err := BuildOnion(nil, []byte("x"), time.Now()); err == nil {
		t.Fatal("empty route must error")
	}
}

// Layers pad to size classes, so two different small payloads produce equal-sized
// ciphertext — a relay can't read content size from layer length.
func TestLayerPaddingBuckets(t *testing.T) {
	h, priv := hop(t)
	ttl := time.Unix(1700000000, 0)

	a, err := BuildOnion([]Hop{h}, []byte("short"), ttl)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildOnion([]Hop{h}, make([]byte, 300), ttl)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.EncryptedLayer) != len(b.EncryptedLayer) {
		t.Fatalf("small payloads must bucket equally: %d vs %d", len(a.EncryptedLayer), len(b.EncryptedLayer))
	}
	if len(a.EncryptedLayer) != 1024 {
		t.Fatalf("expected the 1KB size class, got %d", len(a.EncryptedLayer))
	}
	// Padding is transparent: the layer still peels to the original payload.
	l, err := PeelOnion(priv, a)
	if err != nil {
		t.Fatal(err)
	}
	if l.NextHop != DeliverHop || string(l.Delivery) != "short" {
		t.Fatalf("padding corrupted the layer: %+v", l)
	}
}

// The ladder buckets up to a 64MB top class (above the ~35MB message ceiling),
// then rounds to the nearest MB so per-layer nesting can't cascade coarse classes.
func TestLayerBucketLadder(t *testing.T) {
	const mb = 1024 * 1024
	cases := []struct {
		in   int
		want uint32
	}{
		{0, 1024},
		{100, 1024},
		{5 * mb, 16 * mb},      // 5 MB → 16 MB class
		{17 * mb, 36 * mb},     // 17 MB → 36 MB top class (hidden among 16–36 MB)
		{35 * mb, 36 * mb},     // ceiling message → top class
		{36*mb - 100, 36 * mb}, // just under the top class
		{36 * mb, 37 * mb},     // exactly the top class (+4 prefix) → round up 1 MB
		{40 * mb, 41 * mb},     // above top → round to nearest MB
	}
	for _, c := range cases {
		if got := layerBucket(c.in); got != c.want {
			t.Errorf("layerBucket(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// Only the innermost layer is bucketed: outer (forwarding) layers add just routing
// overhead, so a small message's entry packet stays near the inner bucket instead
// of cascading up to the next size class on each hop.
func TestOuterLayersNotRebucketed(t *testing.T) {
	entry, _ := hop(t)
	middle, _ := hop(t)
	exit, _ := hop(t)

	pkt, err := BuildOnion([]Hop{entry, middle, exit}, []byte("tiny"), time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Inner delivery layer is the 1KB class; the entry layer is inner + 2 hops of
	// routing overhead — must stay well under the next class (4KB), not cascade.
	if got := len(pkt.EncryptedLayer); got >= 4096 {
		t.Fatalf("entry layer = %d bytes; outer layers must not re-bucket (want < 4096)", got)
	}
}

func TestPeelMalformed(t *testing.T) {
	_, priv := mustKeyPair(t)
	if _, err := PeelOnion(priv, &dmcnpb.OnionPacket{EphemeralPub: []byte{1, 2}}); err == nil {
		t.Fatal("malformed packet must error")
	}
}
