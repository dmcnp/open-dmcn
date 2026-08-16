package bridge_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	leveldbds "github.com/ipfs/go-ds-leveldb"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/relay"
)

// The split (v2) envelope the bridge now produces is accepted by the durable
// MailboxStore — which rejects non-split (v1) envelopes — so bridged mail can
// land in the recipient's mailbox and be read by the web client. This is the
// concrete payoff of the unification.
func TestBridgeEnvelopeAcceptedByMailbox(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	recipientKP := mustKeyPair(t)
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, recipientKP), nil
	}
	store := &capturingStore{}
	h := newInbound(passingAuth(), lookup, store.fn, bridgeKP)

	if err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "alice@bridge.localhost", []byte("From: ext@gmail.com\r\n\r\nhi")); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if store.env == nil {
		t.Fatal("nothing delivered")
	}

	d, err := leveldbds.NewDatastore(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("open ds: %v", err)
	}
	defer d.Close()
	mbox := relay.NewMailboxStore(d)
	rxHex := fmt.Sprintf("%x", recipientKP.X25519Public[:])

	if err := mbox.Store(context.Background(), rxHex, [32]byte{1}, store.env, time.Now().UTC()); err != nil {
		t.Fatalf("mailbox must accept the bridge's split envelope: %v", err)
	}
	if n, err := mbox.Count(context.Background(), rxHex); err != nil || n != 1 {
		t.Fatalf("mailbox count = %d (err %v), want 1", n, err)
	}
}
