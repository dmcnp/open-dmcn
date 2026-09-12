package relay

import (
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// selfRetire builds the removal record an address signs for ITSELF: it tombstones its own key,
// and it is signed by that same key rather than by the domain root.
func selfRetire(t *testing.T, rec *identity.IdentityRecord, kp *identity.IdentityKeyPair) *identity.AddressRemovalRecord {
	t.Helper()
	rm, err := identity.NewAddressRemovalRecord(rebindDomain, rec.Address, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rm.RemovedBindings = append(rm.RemovedBindings, identity.RemovedBinding{
		Ed25519Public: rec.Ed25519Public, RemovedAt: time.Now().UTC(),
	})
	if err := rm.Sign(kp); err != nil {
		t.Fatal(err)
	}
	return rm
}

// mkRebindRecordKP is mkRebindRecord, handing back the keypair so the record can sign for itself.
func mkRebindRecordKP(t *testing.T, address string) (*identity.IdentityRecord, *identity.IdentityKeyPair) {
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

// The holder of an address can always stop being reachable at it, with no operator involved. This
// is the whole point of self-retirement: the key that owns the binding may end it.
func TestSelfRetirementIsAccepted(t *testing.T) {
	r, _ := newRebindRelay(t)
	rec, kp := mkRebindRecordKP(t, rebindAddress)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, rec.ToProto()); !ok {
		t.Fatalf("genesis binding refused: %s", reason)
	}
	rm := selfRetire(t, rec, kp)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, rm.ToProto()); !ok {
		t.Fatalf("owner-signed retirement refused: %s", reason)
	}
}

// THE load-bearing negative. Suppression is safe to delegate to the key; authorising a DIFFERENT
// key to take the address is not. If a self-signed retirement opened the rebind gate, a stolen key
// could authorise its own replacement and key compromise would stop being recoverable — it would
// become a permanent address takeover.
func TestSelfRetirementDoesNotAuthoriseRebind(t *testing.T) {
	r, _ := newRebindRelay(t)
	incumbent, kp := mkRebindRecordKP(t, rebindAddress)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, incumbent.ToProto()); !ok {
		t.Fatalf("genesis binding refused: %s", reason)
	}
	rm := selfRetire(t, incumbent, kp)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, rm.ToProto()); !ok {
		t.Fatalf("owner-signed retirement refused: %s", reason)
	}

	attacker := mkRebindRecord(t, rebindAddress)
	ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, attacker.ToProto())
	if ok {
		t.Fatal("TAKEOVER: an owner-signed retirement let a different key take the address — a stolen key could now make its own theft permanent")
	}
	if !strings.HasPrefix(reason, ReasonRebindNeedsRemoval) {
		t.Fatalf("rejected for the wrong reason: %s", reason)
	}
}

// The operator override survives: after a holder retires an address, the domain root can still
// tombstone and reissue it. Root outranks owner, which is what keeps rotation and recovery working.
func TestRootTombstoneStillWorksAfterSelfRetirement(t *testing.T) {
	r, root := newRebindRelay(t)
	incumbent, kp := mkRebindRecordKP(t, rebindAddress)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, incumbent.ToProto()); !ok {
		t.Fatalf("genesis binding refused: %s", reason)
	}
	owner := selfRetire(t, incumbent, kp)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, owner.ToProto()); !ok {
		t.Fatalf("owner-signed retirement refused: %s", reason)
	}

	// The operator's record must carry the owner's binding forward — the append-only rule — which
	// is exactly what the fleet-union rebuild in appendRemovedBinding does.
	rootRm, err := identity.NewAddressRemovalRecord(rebindDomain, rebindAddress, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rootRm.Revision = owner.Revision + 1
	rootRm.RemovedBindings = append(rootRm.RemovedBindings, owner.RemovedBindings...)
	if err := rootRm.Sign(root); err != nil {
		t.Fatal(err)
	}
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, rootRm.ToProto()); !ok {
		t.Fatalf("a root tombstone must be able to displace an owner-signed one: %s", reason)
	}
	successor := mkRebindRecord(t, rebindAddress)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, successor.ToProto()); !ok {
		t.Fatalf("recovery after a root tombstone refused: %s — this is the only recovery path, it must work", reason)
	}
}

// The other half of precedence. A stolen key must not be able to overwrite the operator's
// tombstone, because doing so would shut the rebind gate and block the legitimate recovery the
// root-only rule exists to preserve.
func TestOwnerSignedCannotDisplaceRootSigned(t *testing.T) {
	r, root := newRebindRelay(t)
	incumbent, kp := mkRebindRecordKP(t, rebindAddress)
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, incumbent.ToProto()); !ok {
		t.Fatalf("genesis binding refused: %s", reason)
	}
	rootRm, err := identity.NewAddressRemovalRecord(rebindDomain, rebindAddress, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rootRm.RemovedBindings = append(rootRm.RemovedBindings, identity.RemovedBinding{
		Ed25519Public: incumbent.Ed25519Public, RemovedAt: time.Now().UTC(),
	})
	if err := rootRm.Sign(root); err != nil {
		t.Fatal(err)
	}
	if ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, rootRm.ToProto()); !ok {
		t.Fatalf("root tombstone refused: %s", reason)
	}

	owner := selfRetire(t, incumbent, kp)
	owner.Revision = rootRm.Revision + 1 // even a NEWER revision must not win
	if err := owner.Sign(kp); err != nil {
		t.Fatal(err)
	}
	ok, reason := acceptProto(t, r, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, owner.ToProto())
	if ok {
		t.Fatal("an owner-signed removal displaced a root-signed one — a stolen key could block the operator's recovery")
	}
	if !strings.Contains(reason, "displace") {
		t.Fatalf("rejected for the wrong reason: %s", reason)
	}
}

// Removed() matches on the key alone, so a retirement has to be bound to the address it names —
// otherwise retiring one address would suppress every other address the same key holds.
func TestSelfRetirementIsBoundToItsAddress(t *testing.T) {
	rec, kp := mkRebindRecordKP(t, rebindAddress)
	rm := selfRetire(t, rec, kp)

	if !identity.RemovalIsOwnerSigned(rec, rm) {
		t.Fatal("a record's own retirement should verify against it")
	}
	other, _ := mkRebindRecordKP(t, "bob@example.com")
	if identity.RemovalIsOwnerSigned(other, rm) {
		t.Fatal("a retirement naming one address must not verify against another")
	}
	// And it is emphatically not root-signed, which is what keeps it away from the rebind gate.
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
	if identity.RemovalIsRootSigned(dar, rm) {
		t.Fatal("an owner-signed retirement must never read as root-signed — the rebind gate asks exactly that question")
	}
	if !identity.RemovalSuppresses(rec, dar, rm) {
		t.Fatal("an owner-signed retirement must still suppress the binding")
	}
}
