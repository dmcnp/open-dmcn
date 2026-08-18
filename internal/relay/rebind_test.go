package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

const rebindDomain = "example.com"
const rebindAddress = "alice@example.com"

// newRebindRelay returns a relay holding the domain's DAR — the state the key-continuity rule is
// evaluated against.
func newRebindRelay(t *testing.T) (*Relay, *identity.IdentityKeyPair) {
	t.Helper()
	root, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dar, err := identity.NewDomainAuthorityRecord(rebindDomain, root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	h := newTestHost(t)
	t.Cleanup(func() { h.Close() })
	r := New(h, nfLookup, WithRecordStore(newRecords(t)))
	if err := r.records.PutDAR(context.Background(), dar); err != nil {
		t.Fatal(err)
	}
	return r, root
}

func mkRebindRecord(t *testing.T, address string) *identity.IdentityRecord {
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
	return rec
}

func acceptProto(t *testing.T, r *Relay, kind dmcnpb.RecordKind, msg proto.Message) (bool, string) {
	t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return r.AcceptRecord(context.Background(), kind, data)
}

// TestAcceptRecordRebindRequiresTombstone: a correctly self-signed record for an address already
// bound to a different key must be refused, and the incumbent must survive. Without this, anyone
// who can push a record to a dmcnd instance could take over any address on it — the daemon's own
// registration path publishes through the same store.
func TestAcceptRecordRebindRequiresTombstone(t *testing.T) {
	r, root := newRebindRelay(t)

	incumbent := mkRebindRecord(t, rebindAddress)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, incumbent.ToProto()); !ok {
		t.Fatalf("genesis binding refused: %s", reason)
	}

	attacker := mkRebindRecord(t, rebindAddress)
	ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, attacker.ToProto())
	if ok {
		t.Fatal("takeover accepted: a different key replaced a live binding with no root tombstone")
	}
	if !strings.HasPrefix(reason, ReasonRebindNeedsRemoval) {
		t.Fatalf("rejected for the wrong reason: %s", reason)
	}
	got, err := r.records.GetIdentity(context.Background(), rebindAddress)
	if err != nil || got == nil || string(got.Ed25519Public) != string(incumbent.Ed25519Public) {
		t.Fatal("a rejected rebind disturbed the incumbent record")
	}

	// With the root-signed tombstone — what `dmcndcli remove-address` publishes — it succeeds.
	rm, err := identity.NewAddressRemovalRecord(rebindDomain, rebindAddress, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rm.RemovedBindings = append(rm.RemovedBindings, identity.RemovedBinding{
		Ed25519Public: incumbent.Ed25519Public, RemovedAt: time.Now().UTC(),
	})
	if err := rm.Sign(root); err != nil {
		t.Fatal(err)
	}
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, rm.ToProto()); !ok {
		t.Fatalf("root tombstone refused: %s", reason)
	}
	successor := mkRebindRecord(t, rebindAddress)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, successor.ToProto()); !ok {
		t.Fatalf("recovery after a root tombstone refused: %s — this is the only recovery path, it must work", reason)
	}
}

// A tombstone signed by anyone but the domain root proves nothing and must not be storable.
func TestAcceptRecordForgedTombstoneRejected(t *testing.T) {
	r, _ := newRebindRelay(t)
	incumbent := mkRebindRecord(t, rebindAddress)
	acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, incumbent.ToProto())

	attackerRoot, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rm, err := identity.NewAddressRemovalRecord(rebindDomain, rebindAddress, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rm.RemovedBindings = append(rm.RemovedBindings, identity.RemovedBinding{
		Ed25519Public: incumbent.Ed25519Public, RemovedAt: time.Now().UTC(),
	})
	if err := rm.Sign(attackerRoot); err != nil {
		t.Fatal(err)
	}
	if ok, _ := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, rm.ToProto()); ok {
		t.Fatal("forged tombstone stored")
	}
	if ok, _ := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, mkRebindRecord(t, rebindAddress).ToProto()); ok {
		t.Fatal("rebind accepted after a forged tombstone")
	}
}

// A DAR is self-anchoring, so without root-key continuity any peer could install one naming its own
// root — and everything downstream that trusts the local DAR, including the rebind gate, follows.
func TestAcceptRecordDARRequiresKeyContinuity(t *testing.T) {
	r, root := newRebindRelay(t)
	evilRoot, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	evil, err := identity.NewDomainAuthorityRecord(rebindDomain, evilRoot, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	evil.Revision = 999
	if err := evil.Sign(evilRoot); err != nil {
		t.Fatal(err)
	}
	if ok, _ := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_DAR, evil.ToProto()); ok {
		t.Fatal("forged high-revision DAR accepted")
	}
	stored, err := r.records.GetDAR(context.Background(), rebindDomain)
	if err != nil || stored == nil || !darAcknowledges(stored, root.Ed25519Public) {
		t.Fatal("stored DAR no longer names the legitimate root")
	}
}
