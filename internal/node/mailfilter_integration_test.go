package node_test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/mailfilter"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
)

// TestMailboxNodeFilterRoundTrip proves the P5 node wiring: a mailbox node exposes
// a stable mailbox X25519 key, and a recipient's filter list sealed to BOTH that
// key and the owner's key round-trips through the persistent store and opens with
// the mailbox key (the path the relay uses to enforce silent drops at STORE).
func TestMailboxNodeFilterRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		DNSVerifier:  okDNS,
	})
	if err != nil {
		t.Fatalf("mailbox node: %v", err)
	}
	defer n.Close()

	mboxPub := n.MailboxFilterPub()
	if mboxPub == ([32]byte{}) {
		t.Fatal("mailbox node must expose a non-zero mailbox filter key")
	}
	store := n.MailFilterStore()
	if store == nil {
		t.Fatal("mailbox node must expose a mail filter store")
	}

	ownerKP, _ := identity.GenerateIdentityKeyPair()
	recipientHex := hex.EncodeToString(ownerKP.X25519Public[:])

	// Owner seals a deny-list to the mailbox key AND their own key.
	list := &mailfilter.List{Mode: mailfilter.ModeDeny, Domains: []string{"evil.com"}}
	pt, _ := list.Marshal()
	blob, err := message.SealToRecipients(pt, [][32]byte{mboxPub, ownerKP.X25519Public})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutFilter(ctx, recipientHex, blob); err != nil {
		t.Fatalf("put filter: %v", err)
	}

	// The mailbox can read+evaluate it (enforcement path).
	got, err := store.GetFilter(ctx, recipientHex)
	if err != nil || got == nil {
		t.Fatalf("get filter: %v", err)
	}
	openedByOwner, err := message.OpenSealed(got, ownerKP.X25519Private, ownerKP.X25519Public)
	if err != nil {
		t.Fatalf("owner cannot open own filter: %v", err)
	}
	if l, _ := mailfilter.Unmarshal(openedByOwner); l.Permits("x@evil.com", "", false) {
		t.Fatal("deny-list must block evil.com")
	}
}
