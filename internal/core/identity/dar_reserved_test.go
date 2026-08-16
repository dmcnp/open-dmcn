package identity

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// TestReservedLocalPartsRoundTripAndSigned checks the reserved list round-trips through proto,
// stays covered by the DAR self-signature (even with mixed-case entries — the round-trip must be
// byte-faithful), and that ReservesLocalPart matches case-insensitively against the list only.
func TestReservedLocalPartsRoundTripAndSigned(t *testing.T) {
	root, _ := GenerateIdentityKeyPair()
	dar, err := NewDomainAuthorityRecord("reserved.test", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Mixed case on purpose: FromProto/ToProto must NOT normalize, or Verify() would break.
	dar.ReservedLocalParts = []string{"Admin", "press"}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}

	data, err := proto.Marshal(dar.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	pb := &dmcnpb.DomainAuthorityRecord{}
	if err := proto.Unmarshal(data, pb); err != nil {
		t.Fatal(err)
	}
	got, err := DomainAuthorityRecordFromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("self-signature must still verify with reserved list set: %v", err)
	}

	// Case-insensitive match against listed entries (regardless of stored case).
	for _, lp := range []string{"admin", "ADMIN", "Admin", "press", "  press  "} {
		if !got.ReservesLocalPart(lp) {
			t.Errorf("ReservesLocalPart(%q) = false, want true", lp)
		}
	}
	// Not in the list → not reserved (no baseline floor: postmaster is unlisted here).
	for _, lp := range []string{"alice", "postmaster", ""} {
		if got.ReservesLocalPart(lp) {
			t.Errorf("ReservesLocalPart(%q) = true, want false", lp)
		}
	}
}

// TestReservedEmptyListReservesNothing confirms there is no hardcoded baseline floor: a DAR with
// an empty reserved list reserves nothing (default names like postmaster are registrable unless
// explicitly listed).
func TestReservedEmptyListReservesNothing(t *testing.T) {
	root, _ := GenerateIdentityKeyPair()
	dar, err := NewDomainAuthorityRecord("empty.test", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, lp := range append([]string{"admin"}, DefaultReservedLocalParts...) {
		if dar.ReservesLocalPart(lp) {
			t.Errorf("empty-list DAR reserved %q, want nothing reserved", lp)
		}
	}
}
