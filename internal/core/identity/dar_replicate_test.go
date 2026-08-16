package identity

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// TestDARReplicateMailboxFlag checks the declared-only mailbox replication policy bit
// defaults off, round-trips through proto, and is covered by the DAR self-signature.
func TestDARReplicateMailboxFlag(t *testing.T) {
	root, _ := GenerateIdentityKeyPair()
	dar, err := NewDomainAuthorityRecord("replicate.test", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if dar.ReplicatesMailbox() {
		t.Fatal("replicate-mailbox must default to off (failover)")
	}

	dar.PolicyFlags |= PolicyReplicateMailbox
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
	if !got.ReplicatesMailbox() {
		t.Fatal("replicate-mailbox flag lost in round trip")
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("self-signature must still verify with the flag set: %v", err)
	}
}
