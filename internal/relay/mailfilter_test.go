package relay

import (
	"context"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/mailfilter"
	"dmcn.dev/open-dmcn/internal/core/message"
)

type stubFilterStore map[string]*message.SealedBlob

func (s stubFilterStore) GetFilter(_ context.Context, hex string) (*message.SealedBlob, error) {
	return s[hex], nil
}

func (s stubFilterStore) PutFilter(_ context.Context, hex string, blob *message.SealedBlob) error {
	s[hex] = blob
	return nil
}

func (s stubFilterStore) DeleteFilter(_ context.Context, hex string) error {
	delete(s, hex)
	return nil
}

func sealedList(t *testing.T, l *mailfilter.List, mailboxPub [32]byte) *message.SealedBlob {
	t.Helper()
	pt, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := message.SealToRecipients(pt, [][32]byte{mailboxPub})
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// TestMailFilterSilentDrop proves recipient filtering: a STORE from a sender on
// the recipient's deny-list is silently dropped (the sender gets a normal,
// error-free ACK; nothing is stored), while an unfiltered sender is stored.
func TestMailFilterSilentDrop(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	const senderAddr = "spammer@evil.com"

	mboxPub, mboxPriv, _ := crypto.GenerateX25519KeyPair()

	h := newTestHost(t)
	defer h.Close()

	sr, recipientHex := buildStoreRequest(t, senderAddr, senderKP, recipientKP)

	// Recipient blocks the sender's whole domain.
	store := stubFilterStore{
		recipientHex: sealedList(t, &mailfilter.List{Mode: mailfilter.ModeDeny, Domains: []string{"evil.com"}}, mboxPub),
	}
	r := New(h, senderLookup(senderAddr, senderKP), WithMailboxFilter(store, mboxPriv, mboxPub, nil))

	resp := r.handleStore(h.ID(), sr)
	if resp.GetError() != nil {
		t.Fatalf("filtered STORE must still ACK without error (silent drop), got %v", resp.GetError())
	}
	if envs, _ := r.Store().Fetch(recipientHex); len(envs) != 0 {
		t.Fatalf("blocked sender's message must not be stored, got %d", len(envs))
	}

	// A recipient with no filter (different key) stores normally.
	other := stubFilterStore{} // no entry ⇒ permit
	r2 := New(newTestHost(t), senderLookup(senderAddr, senderKP), WithMailboxFilter(other, mboxPriv, mboxPub, nil))
	sr2, recipientHex2 := buildStoreRequest(t, senderAddr, senderKP, recipientKP)
	if resp := r2.handleStore(h.ID(), sr2); resp.GetError() != nil {
		t.Fatalf("unfiltered STORE should succeed, got %v", resp.GetError())
	}
	if envs, _ := r2.Store().Fetch(recipientHex2); len(envs) != 1 {
		t.Fatalf("unfiltered sender's message should be stored, got %d", len(envs))
	}
}
