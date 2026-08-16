package identity

import (
	"bytes"
	"testing"
	"time"
)

func mustKP(t *testing.T) *IdentityKeyPair {
	t.Helper()
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	return kp
}

// TestPolicyFlagsRoundTripAndSigned verifies the policy bits survive proto
// round-trip and are covered by the DAR self-signature (tampering breaks Verify).
func TestPolicyFlagsRoundTripAndSigned(t *testing.T) {
	root := mustKP(t)
	dar, err := NewDomainAuthorityRecord("dmcn.me", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if dar.RequiresCountersign() || dar.ReplicatesMailbox() {
		t.Fatal("fresh DAR should have no policy bits")
	}
	dar.PolicyFlags |= PolicyRequireCountersign | PolicyReplicateMailbox
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}

	got, err := DomainAuthorityRecordFromProto(dar.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequiresCountersign() || !got.ReplicatesMailbox() {
		t.Fatalf("policy bits lost in round-trip: flags=%d", got.PolicyFlags)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("round-tripped DAR self-signature invalid: %v", err)
	}

	// Flipping a policy bit after signing must invalidate the self-signature.
	got.PolicyFlags &^= PolicyReplicateMailbox
	if err := got.Verify(); err == nil {
		t.Fatal("expected tampered PolicyFlags to break the DAR self-signature")
	}
}

// TestFleetDomainRoundTripAndSigned verifies the fleet deferral survives proto round-trip
// and is covered by the DAR self-signature (tampering breaks Verify).
func TestFleetDomainRoundTripAndSigned(t *testing.T) {
	root := mustKP(t)
	dar, err := NewDomainAuthorityRecord("dmcn.email", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dar.DefersToFleet(); ok {
		t.Fatal("fresh DAR should not defer to a fleet")
	}
	dar.FleetDomain = "dmcnmail.com"
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	got, err := DomainAuthorityRecordFromProto(dar.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := got.DefersToFleet(); !ok || f != "dmcnmail.com" {
		t.Fatalf("fleet deferral lost: got %q, ok=%v", f, ok)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("round-tripped DAR self-signature invalid: %v", err)
	}
	// Tampering with the fleet deferral after signing must break the self-signature —
	// this is what makes the DNS fleet= pointer cryptographically confirmable.
	got.FleetDomain = "attacker.example"
	if err := got.Verify(); err == nil {
		t.Fatal("expected tampered FleetDomain to break the DAR self-signature")
	}
}

func TestDARSignVerifyFingerprintProto(t *testing.T) {
	root := mustKP(t)
	dar, err := NewDomainAuthorityRecord("dmcn.me", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := dar.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Fingerprint must equal the fingerprint of the root key material.
	want := fingerprintOf(root.Ed25519Public, root.X25519Public)
	if dar.Fingerprint() != want {
		t.Fatalf("Fingerprint = %s, want %s", dar.Fingerprint(), want)
	}

	// Proto round-trip preserves the record and signature.
	pb := dar.ToProto()
	data, err := protoMarshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DomainAuthorityRecordFromProtoBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
	if got.Fingerprint() != dar.Fingerprint() || got.Revision != dar.Revision {
		t.Fatal("round-trip mismatch")
	}

	// Tamper: changing the revision after signing breaks the self-signature.
	got.Revision++
	if err := got.Verify(); err == nil {
		t.Fatal("expected DAR verify to fail after tampering")
	}
}

func TestRootKeyAtTimeline(t *testing.T) {
	k0, k1, k2 := mustKP(t), mustKP(t), mustKP(t)
	t0 := time.Unix(1_000, 0).UTC()
	t1 := time.Unix(2_000, 0).UTC()
	t2 := time.Unix(3_000, 0).UTC()

	dar := &DomainAuthorityRecord{
		Domain:                 "dmcn.me",
		AuthorityEd25519:       k2.Ed25519Public,
		AuthorityEffectiveFrom: t2,
		SupersededKeys: []AuthorityKey{
			{Ed25519Public: k0.Ed25519Public, EffectiveFrom: t0},
			{Ed25519Public: k1.Ed25519Public, EffectiveFrom: t1},
		},
	}

	if _, ok := dar.RootKeyAt(time.Unix(500, 0).UTC()); ok {
		t.Fatal("expected no key before genesis")
	}
	if pub, _ := dar.RootKeyAt(time.Unix(1_500, 0).UTC()); !bytes.Equal(pub, k0.Ed25519Public) {
		t.Fatal("expected k0 in [t0,t1)")
	}
	if pub, _ := dar.RootKeyAt(t1); !bytes.Equal(pub, k1.Ed25519Public) {
		t.Fatal("expected k1 at t1")
	}
	if pub, _ := dar.RootKeyAt(time.Unix(9_999, 0).UTC()); !bytes.Equal(pub, k2.Ed25519Public) {
		t.Fatal("expected current key k2 after t2")
	}
}

func TestAddressRemovalRecord(t *testing.T) {
	root := mustKP(t)
	victim := mustKP(t)
	other := mustKP(t)

	rm, err := NewAddressRemovalRecord("dmcn.me", "alice@dmcn.me", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rm.RemovedBindings = append(rm.RemovedBindings, RemovedBinding{
		Ed25519Public: victim.Ed25519Public,
		RemovedAt:     time.Now(),
	})
	if err := rm.Sign(root); err != nil {
		t.Fatal(err)
	}
	if err := rm.Verify(root.Ed25519Public); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := rm.Verify(other.Ed25519Public); err == nil {
		t.Fatal("removal must not verify against a different key")
	}
	if _, ok := rm.Removed(victim.Ed25519Public); !ok {
		t.Fatal("victim key should be reported removed")
	}
	if _, ok := rm.Removed(other.Ed25519Public); ok {
		t.Fatal("untouched key should not be reported removed")
	}

	// Proto round-trip.
	data, _ := protoMarshal(rm.ToProto())
	got, err := AddressRemovalRecordFromProtoBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(root.Ed25519Public); err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
	if _, ok := got.Removed(victim.Ed25519Public); !ok {
		t.Fatal("victim key missing after round-trip")
	}
}

func TestValidateDomain(t *testing.T) {
	if err := validateDomain("dmcn.me"); err != nil {
		t.Fatalf("valid domain rejected: %v", err)
	}
	if err := validateDomain(""); err == nil {
		t.Fatal("empty domain should be rejected")
	}
	if err := validateDomain("alice@dmcn.me"); err == nil {
		t.Fatal("domain with @ should be rejected")
	}
}
