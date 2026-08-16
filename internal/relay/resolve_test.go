package relay

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/dmcnpb"
)

func newRecords(t *testing.T) *RecordStore {
	t.Helper()
	d := openMailboxDS(t, t.TempDir())
	t.Cleanup(func() { d.Close() })
	return NewRecordStore(d)
}

func signedIdentity(t *testing.T, address string) (*identity.IdentityRecord, *identity.IdentityKeyPair) {
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
	return rec, kp
}

// TestRecordStoreRoundTrip verifies each record kind survives a put/get and that a missing
// record returns (nil, nil).
func TestRecordStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	rs := newRecords(t)

	rec, _ := signedIdentity(t, "alice@dmcn.email")
	if err := rs.PutIdentity(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := rs.GetIdentity(ctx, "alice@dmcn.email")
	if err != nil || got == nil {
		t.Fatalf("GetIdentity = (%v, %v)", got, err)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("served identity failed self-verify: %v", err)
	}
	if miss, err := rs.GetIdentityBytes(ctx, "nobody@dmcn.email"); err != nil || miss != nil {
		t.Fatalf("missing identity = (%v, %v), want (nil, nil)", miss, err)
	}

	roster, _ := identity.NewFleetRoster("dmcnmail.com", time.Now())
	roster.Nodes = []identity.FleetNode{{PeerID: "12D3KooWA", Multiaddrs: []string{"/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWA"}}}
	if err := rs.PutRoster(ctx, roster); err != nil {
		t.Fatal(err)
	}
	if data, err := rs.GetRosterBytes(ctx, "dmcnmail.com"); err != nil || data == nil {
		t.Fatalf("GetRosterBytes = (%v, %v)", data, err)
	}
}

// TestResolveIdentityOverWire runs the full get-identity op between two hosts: a serving fleet
// node with a populated RecordStore, and a client fetching the signed record bytes.
func TestResolveIdentityOverWire(t *testing.T) {
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

	rec, _ := signedIdentity(t, "alice@dmcn.email")
	records := newRecords(t)
	if err := records.PutIdentity(ctx, rec); err != nil {
		t.Fatal(err)
	}

	server := New(h1, nfLookup, WithRecordStore(records))
	server.Start()
	defer server.Stop()
	client := New(h2, nfLookup)

	// Present record: the client gets bytes that re-parse and self-verify.
	data, err := client.ClientGetIdentity(ctx, h1.ID(), "alice@dmcn.email")
	if err != nil {
		t.Fatalf("ClientGetIdentity: %v", err)
	}
	got, err := identity.IdentityRecordFromProtoBytes(data)
	if err != nil {
		t.Fatalf("re-parse served record: %v", err)
	}
	if got.Address != "alice@dmcn.email" || got.Verify() != nil {
		t.Fatalf("served record wrong/invalid: addr=%s verify=%v", got.Address, got.Verify())
	}

	// Absent record: not-found surfaces as (nil, nil), not an error.
	miss, err := client.ClientGetIdentity(ctx, h1.ID(), "nobody@dmcn.email")
	if err != nil || miss != nil {
		t.Fatalf("absent record = (%v, %v), want (nil, nil)", miss, err)
	}
}

// TestPutRecordAndAntiRollback: a routing-granted pusher replicates a signed record to a serving
// node, which then serves it; a stale-revision push is rejected; an ungranted pusher is refused.
func TestPutRecordAndAntiRollback(t *testing.T) {
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

	// open-dmcn: a single self-hosted node accepts self-authenticating identity pushes for
	// its domain (no fleet routing-grant gate); anti-rollback by revision still applies.
	server := New(h1, nfLookup, WithRecordStore(newRecords(t)))
	server.Start()
	defer server.Stop()
	client := New(h2, nfLookup)

	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(rev uint64) []byte {
		rec, _ := identity.NewIdentityRecord("alice@dmcn.email", kp)
		rec.Revision = rev
		if err := rec.Sign(kp); err != nil {
			t.Fatal(err)
		}
		data, _ := proto.Marshal(rec.ToProto())
		return data
	}

	// Push rev 1 → accepted and served.
	ok, reason, err := client.ClientPutRecord(ctx, h1.ID(), dmcnpb.RecordKind_RECORD_KIND_IDENTITY, sign(1))
	if err != nil || !ok {
		t.Fatalf("push rev1 = (%t, %q, %v), want accepted", ok, reason, err)
	}
	got, err := client.ClientGetIdentity(ctx, h1.ID(), "alice@dmcn.email")
	if err != nil || got == nil {
		t.Fatalf("serve after push = (%v, %v)", got, err)
	}

	// Push rev 2 → accepted (newer).
	if ok, reason, err := client.ClientPutRecord(ctx, h1.ID(), dmcnpb.RecordKind_RECORD_KIND_IDENTITY, sign(2)); err != nil || !ok {
		t.Fatalf("push rev2 = (%t, %q, %v), want accepted", ok, reason, err)
	}
	// Push rev 1 again → rejected (stale, anti-rollback).
	if ok, _, err := client.ClientPutRecord(ctx, h1.ID(), dmcnpb.RecordKind_RECORD_KIND_IDENTITY, sign(1)); err != nil || ok {
		t.Fatalf("stale rev1 push accepted=%t err=%v, want rejected", ok, err)
	}

}
