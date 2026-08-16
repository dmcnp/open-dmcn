package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	leveldbds "github.com/ipfs/go-ds-leveldb"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/dmcnpb"
)

func openMailboxDS(t *testing.T, dir string) *leveldbds.Datastore {
	t.Helper()
	d, err := leveldbds.NewDatastore(dir, nil)
	if err != nil {
		t.Fatalf("leveldb: %v", err)
	}
	return d
}

// mailboxTestRecipient returns a fresh X25519 recipient keypair and its hex id.
func mailboxTestRecipient(t *testing.T) (pub, priv [32]byte, hexID string) {
	t.Helper()
	xPub, xPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return xPub, xPriv, hex.EncodeToString(xPub[:])
}

// makeSplitEnvelope composes a message, splits + encrypts it for the recipient,
// and returns the split envelope plus its relay hash.
func makeSplitEnvelope(t *testing.T, rxPub [32]byte, subject, body string) (*message.EncryptedEnvelope, [32]byte) {
	t.Helper()
	senderPub, senderPriv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := message.NewPlaintextMessage("alice@dmcn.me", "bob@dmcn.me", subject, body, senderPub)
	if err != nil {
		t.Fatal(err)
	}
	sh, content, err := message.Split(msg, senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := proto.Marshal(env.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	return env, crypto.SHA256Hash(b)
}

func TestMailboxListPaginates(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	mbox := NewMailboxStore(d)

	rxPub, _, rxHex := mailboxTestRecipient(t)

	const n = 7
	base := time.Unix(1_700_000_000, 0)
	want := make(map[[32]byte]bool, n)
	for i := 0; i < n; i++ {
		env, hash := makeSplitEnvelope(t, rxPub, "msg", "body content")
		if err := mbox.Store(ctx, rxHex, hash, env, base.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
		want[hash] = true
	}

	// Drain pages with limit 3; collect every hash exactly once, in stored order.
	got := make(map[[32]byte]bool, n)
	var order []int64
	cursor := ""
	pages := 0
	for {
		entries, next, err := mbox.List(ctx, rxHex, 3, cursor)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		pages++
		for _, e := range entries {
			var h [32]byte
			copy(h[:], e.Hash)
			if got[h] {
				t.Fatalf("duplicate hash across pages: %x", h)
			}
			got[h] = true
			order = append(order, e.StoredAt)
		}
		if next == "" {
			break
		}
		cursor = next
		if pages > n+2 {
			t.Fatal("pagination did not terminate")
		}
	}

	if len(got) != n {
		t.Fatalf("drained %d messages, want %d", len(got), n)
	}
	for h := range want {
		if !got[h] {
			t.Fatalf("missing message %x after draining all pages", h)
		}
	}
	for i := 1; i < len(order); i++ {
		if order[i] < order[i-1] {
			t.Fatalf("pages not in chronological order: %v", order)
		}
	}
}

func TestMailboxBodyRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	mbox := NewMailboxStore(d)

	rxPub, rxPriv, rxHex := mailboxTestRecipient(t)
	env, hash := makeSplitEnvelope(t, rxPub, "Subject Line", "the secret body")
	if err := mbox.Store(ctx, rxHex, hash, env, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("store: %v", err)
	}

	// LIST yields the header view; decrypt it for the preview (no body read).
	entries, _, err := mbox.List(ctx, rxHex, 10, "")
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: %v (n=%d)", err, len(entries))
	}
	entry := entries[0]

	// BODY fetched on open.
	body, err := mbox.GetBody(ctx, rxHex, hash)
	if err != nil {
		t.Fatalf("get body: %v", err)
	}

	// Reassemble the envelope from the two stored parts and decrypt end-to-end.
	rebuilt, err := message.EncryptedEnvelopeFromProto(&dmcnpb.EncryptedEnvelope{
		Recipients:      entry.Recipients,
		EncryptedHeader: entry.EncryptedHeader,
		HeaderNonce:     entry.HeaderNonce,
		HeaderTag:       entry.HeaderTag,
		HeaderSizeClass: entry.HeaderSizeClass,
		EncryptedBody:   body.EncryptedBody,
		BodyNonce:       body.BodyNonce,
		BodyTag:         body.BodyTag,
		BodySizeClass:   body.BodySizeClass,
	})
	if err != nil {
		t.Fatalf("rebuild envelope: %v", err)
	}
	sh, err := message.DecryptHeader(rebuilt, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("decrypt header: %v", err)
	}
	if sh.Header.Subject != "Subject Line" {
		t.Fatalf("header subject = %q", sh.Header.Subject)
	}
	content, err := message.DecryptBody(rebuilt, &sh.Header, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	if string(content.Body.Content) != "the secret body" {
		t.Fatalf("body = %q", content.Body.Content)
	}
}

func TestMailboxDelete(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	mbox := NewMailboxStore(d)

	rxPub, _, rxHex := mailboxTestRecipient(t)
	env1, h1 := makeSplitEnvelope(t, rxPub, "one", "b1")
	env2, h2 := makeSplitEnvelope(t, rxPub, "two", "b2")
	if err := mbox.Store(ctx, rxHex, h1, env1, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := mbox.Store(ctx, rxHex, h2, env2, time.Unix(1_700_000_001, 0)); err != nil {
		t.Fatal(err)
	}

	if err := mbox.Delete(ctx, rxHex, h1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n, _ := mbox.Count(ctx, rxHex); n != 1 {
		t.Fatalf("count after delete = %d, want 1", n)
	}
	if _, err := mbox.GetBody(ctx, rxHex, h1); !errors.Is(err, ErrEnvelopeNotFound) {
		t.Fatalf("deleted body should be gone, got %v", err)
	}
	entries, _, _ := mbox.List(ctx, rxHex, 10, "")
	if len(entries) != 1 {
		t.Fatalf("list after delete = %d entries, want 1", len(entries))
	}
	var remaining [32]byte
	copy(remaining[:], entries[0].Hash)
	if remaining != h2 {
		t.Fatal("wrong message survived delete")
	}
	// Idempotent: deleting again is not an error.
	if err := mbox.Delete(ctx, rxHex, h1); err != nil {
		t.Fatalf("second delete should be a no-op, got %v", err)
	}
}

func TestMailboxStoreDedup(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	mbox := NewMailboxStore(d)

	rxPub, _, rxHex := mailboxTestRecipient(t)
	env, hash := makeSplitEnvelope(t, rxPub, "dup", "body")
	for i := 0; i < 3; i++ {
		if err := mbox.Store(ctx, rxHex, hash, env, time.Unix(1_700_000_000, int64(i))); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	if n, _ := mbox.Count(ctx, rxHex); n != 1 {
		t.Fatalf("count = %d, want 1 (idempotent store)", n)
	}
}

func TestMailboxPersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rxPub, _, rxHex := mailboxTestRecipient(t)

	d1 := openMailboxDS(t, dir)
	mbox1 := NewMailboxStore(d1)
	env, hash := makeSplitEnvelope(t, rxPub, "durable", "outlives a restart")
	if err := mbox1.Store(ctx, rxHex, hash, env, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	d1.Close()

	// Reopen the same directory — the message must still be there (hold-until-deleted).
	d2 := openMailboxDS(t, dir)
	defer d2.Close()
	mbox2 := NewMailboxStore(d2)
	entries, _, err := mbox2.List(ctx, rxHex, 10, "")
	if err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("after restart: %d entries, want 1", len(entries))
	}
	var got [32]byte
	copy(got[:], entries[0].Hash)
	if got != hash {
		t.Fatal("restarted mailbox returned the wrong message")
	}
}
