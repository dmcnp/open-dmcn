package identity

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// TestDARAdminKeyCustodyFlag checks the admin-key-custody policy bit defaults off,
// round-trips through proto, and is covered by the DAR self-signature.
func TestDARAdminKeyCustodyFlag(t *testing.T) {
	root, _ := GenerateIdentityKeyPair()
	dar, err := NewDomainAuthorityRecord("custody.test", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if dar.AdminKeyCustody() {
		t.Fatal("admin-key-custody must default to off (self-service registration)")
	}

	dar.PolicyFlags |= PolicyAdminKeyCustody
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
	if !got.AdminKeyCustody() {
		t.Fatal("admin-key-custody flag lost in round trip")
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("self-signature must still verify with the flag set: %v", err)
	}
	if got.ReplicatesMailbox() || got.RequiresCountersign() || got.RequiresOnion() || got.AllowsRequests() {
		t.Fatal("admin-key-custody bit must not alias any other policy bit")
	}
}
