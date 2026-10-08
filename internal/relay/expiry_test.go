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

// TestExpiredRecordIsRefusedAndNotServed: an expired record is not a binding, so it is neither
// stored on the way in nor served to a reader from a node that still holds it.
func TestExpiredRecordIsRefusedAndNotServed(t *testing.T) {
	ctx := context.Background()
	h := newTestHost(t)
	defer h.Close()
	r := New(h, nfLookup, WithRecordStore(newRecords(t)))

	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	expired, err := identity.NewIdentityRecord("alice@dmcn.email", kp)
	if err != nil {
		t.Fatal(err)
	}
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	if err := expired.Sign(kp); err != nil {
		t.Fatal(err)
	}

	data, err := proto.Marshal(expired.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := r.acceptIdentity(ctx, data); ok || !strings.Contains(reason, "expired") {
		t.Fatalf("acceptIdentity(expired) = %v %q, want a refusal naming the expiry", ok, reason)
	}

	// Stored before it expired, read after.
	if err := r.records.PutIdentity(ctx, expired); err != nil {
		t.Fatal(err)
	}
	resp := r.handleGetIdentity(&dmcnpb.GetIdentityRequest{Address: expired.Address})
	if resp.GetGetIdentity().GetFound() {
		t.Fatal("an expired record was served")
	}
	if rec, _ := r.resolveIdentity(ctx, expired.Address); rec != nil {
		t.Fatal("resolveIdentity answered with an expired local record")
	}
}
