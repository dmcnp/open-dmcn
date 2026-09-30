package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	leveldbds "github.com/ipfs/go-ds-leveldb"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/message"
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

// drainList walks every page of a mailbox in one order and returns the hashes in the order
// they were served.
func drainList(t *testing.T, mbox *MailboxStore, rxHex string, limit int, order ListOrder) [][32]byte {
	t.Helper()
	ctx := context.Background()
	var out [][32]byte
	seen := map[[32]byte]bool{}
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 100 {
			t.Fatal("pagination did not terminate")
		}
		entries, next, err := mbox.List(ctx, rxHex, limit, cursor, order)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, e := range entries {
			var h [32]byte
			copy(h[:], e.Hash)
			if seen[h] {
				t.Fatalf("duplicate hash across pages: %x", h)
			}
			seen[h] = true
			out = append(out, h)
		}
		if next == "" {
			return out
		}
		cursor = next
	}
}

func TestMailboxListPaginates(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	mbox := NewMailboxStore(d)

	rxPub, _, rxHex := mailboxTestRecipient(t)

	// A second apart, so arrival order is visible in StoredAt as well as in the key.
	const n = 7
	base := time.Unix(1_700_000_000, 0)
	var stored [][32]byte
	for i := 0; i < n; i++ {
		env, hash := makeSplitEnvelope(t, rxPub, "msg", "body content")
		if err := mbox.Store(ctx, rxHex, hash, env, base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
		stored = append(stored, hash)
	}

	for _, limit := range []int{1, 3, 7, 50} {
		if got := drainList(t, mbox, rxHex, limit, ListOldestFirst); !slices.Equal(got, stored) {
			t.Fatalf("oldest-first, limit %d: got %x, want arrival order", limit, got)
		}
		newest := slices.Clone(stored)
		slices.Reverse(newest)
		if got := drainList(t, mbox, rxHex, limit, ListNewestFirst); !slices.Equal(got, newest) {
			t.Fatalf("newest-first, limit %d: got %x, want reverse arrival order", limit, got)
		}
	}

	// An exact page leaves nothing behind: no cursor pointing at an empty page.
	if _, next, _ := mbox.List(ctx, rxHex, n, "", ListNewestFirst); next != "" {
		t.Fatalf("a page holding the whole mailbox returned cursor %q", next)
	}
}

// A page stops at the byte budget even under its entry limit, so it always fits a frame, and
// the cursor carries on from where it stopped.
func TestMailboxListByteBudget(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	mbox := NewMailboxStore(d)
	rxPub, _, rxHex := mailboxTestRecipient(t)

	base := time.Unix(1_700_000_000, 0)
	var one int
	for i := 0; i < 10; i++ {
		env, hash := makeSplitEnvelope(t, rxPub, "msg", "body content")
		if err := mbox.Store(ctx, rxHex, hash, env, base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
		if one == 0 {
			entries, _, _ := mbox.List(ctx, rxHex, 1, "", ListNewestFirst)
			one = proto.Size(entries[0])
		}
	}
	defer func(was int) { listByteBudget = was }(listByteBudget)
	listByteBudget = one*3 + one/2

	entries, next, err := mbox.List(ctx, rxHex, 100, "", ListNewestFirst)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || next == "" {
		t.Fatalf("got %d entries and cursor %q; want 3 and a cursor", len(entries), next)
	}
	if got := drainList(t, mbox, rxHex, 100, ListNewestFirst); len(got) != 10 {
		t.Fatalf("drained %d of 10 across byte-limited pages", len(got))
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
	entries, _, err := mbox.List(ctx, rxHex, 10, "", ListOldestFirst)
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
	entries, _, _ := mbox.List(ctx, rxHex, 10, "", ListOldestFirst)
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
	entries, _, err := mbox2.List(ctx, rxHex, 10, "", ListOldestFirst)
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
