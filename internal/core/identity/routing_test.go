package identity

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// TestIssueRoutingCredential checks the routing credential carries the hints, is signed by
// the issuer, and is shaped correctly (role, subject, address).
func TestIssueRoutingCredential(t *testing.T) {
	owner, _ := GenerateIdentityKeyPair()
	op, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", owner)
	if err := rec.Sign(owner); err != nil {
		t.Fatal(err)
	}

	hints := []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA", "/ip4/10.0.0.2/tcp/7400/p2p/QmB"}
	if err := rec.IssueRoutingCredential(op, hints, time.Now()); err != nil {
		t.Fatalf("IssueRoutingCredential: %v", err)
	}
	if !rec.HasRoutingCredential() {
		t.Fatal("expected a routing credential")
	}
	c := rec.RoutingCredential
	if !c.HasRole(RoleRouting) {
		t.Error("routing credential missing RoleRouting")
	}
	if c.Address != rec.Address || string(c.Subject) != string(rec.Ed25519Public) {
		t.Error("routing credential subject/address mismatch")
	}
	if err := c.VerifySignature(); err != nil {
		t.Errorf("routing credential signature invalid: %v", err)
	}
	if !equalHints(c.RelayHints, hints) || !equalHints(rec.RelayHints, hints) {
		t.Errorf("hints not set: cred=%v rec=%v want %v", c.RelayHints, rec.RelayHints, hints)
	}
}

// TestSelfSignatureExcludesRelayHints verifies RelayHints is NOT covered by the owner
// self-signature — so an operator can change it without breaking Verify().
func TestSelfSignatureExcludesRelayHints(t *testing.T) {
	owner, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", owner)
	rec.RelayHints = []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA"}
	if err := rec.Sign(owner); err != nil {
		t.Fatal(err)
	}
	// Change RelayHints after signing — Verify must still pass (it's operator-owned).
	rec.RelayHints = []string{"/ip4/10.0.0.9/tcp/7400/p2p/QmZ"}
	if err := rec.Verify(); err != nil {
		t.Fatalf("Verify() must succeed after changing RelayHints (excluded from self-sig): %v", err)
	}
}

// TestRoutingCredentialProtoRoundTrip checks the routing credential survives a proto round
// trip and that decode mirrors its hints into RelayHints.
func TestRoutingCredentialProtoRoundTrip(t *testing.T) {
	owner, _ := GenerateIdentityKeyPair()
	op, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", owner)
	rec.Sign(owner)
	hints := []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA", "/ip4/10.0.0.2/tcp/7400/p2p/QmB"}
	if err := rec.IssueRoutingCredential(op, hints, time.Now()); err != nil {
		t.Fatal(err)
	}

	data, err := proto.Marshal(rec.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	pb := &dmcnpb.IdentityRecord{}
	if err := proto.Unmarshal(data, pb); err != nil {
		t.Fatal(err)
	}
	got, err := IdentityRecordFromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasRoutingCredential() {
		t.Fatal("routing credential lost in round trip")
	}
	if !equalHints(got.RelayHints, hints) {
		t.Errorf("decoded RelayHints = %v, want %v (mirrored from routing credential)", got.RelayHints, hints)
	}
	if err := got.RoutingCredential.VerifySignature(); err != nil {
		t.Errorf("round-tripped routing credential signature invalid: %v", err)
	}
}

func equalHints(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
