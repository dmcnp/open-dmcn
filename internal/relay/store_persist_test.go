package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"
	dssync "github.com/ipfs/go-datastore/sync"
	leveldbds "github.com/ipfs/go-ds-leveldb"
	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// testEnvelope builds a real encrypted envelope for a fresh recipient.
func testEnvelope(t *testing.T) *message.EncryptedEnvelope {
	t.Helper()
	kp, _ := identity.GenerateIdentityKeyPair()
	msg, _ := message.NewPlaintextMessage("alice@localhost", "bob@localhost", "Subj", "Body", kp.Ed25519Public)
	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(kp.Ed25519Private); err != nil {
		t.Fatalf("sign: %v", err)
	}
	rcpt, _ := identity.GenerateIdentityKeyPair()
	env, err := message.Encrypt(sm, []message.RecipientInfo{{DeviceID: rcpt.DeviceID, X25519Pub: rcpt.X25519Public}})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return env
}

// A durable message store recovers queued envelopes after a restart: a pending
// envelope is still fetchable, and an acked one is gone for good.
func TestMessageStorePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	log := logr.With(logr.M("test", true))
	const addr = "626f62" // arbitrary recipient key hex

	pendingEnv := testEnvelope(t)
	ackedEnv := testEnvelope(t)
	pendingHash := [32]byte{1, 1, 1}
	ackedHash := [32]byte{2, 2, 2}

	// First lifetime: store two envelopes, deliver one, then "crash" (close ds).
	d1, err := leveldbds.NewDatastore(dir, nil)
	if err != nil {
		t.Fatalf("open ds: %v", err)
	}
	s1, err := NewPersistentMessageStore(d1, log)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	s1.Store(addr, pendingEnv, pendingHash)
	s1.Store(addr, ackedEnv, ackedHash)
	s1.MarkFetched(addr, [][32]byte{ackedHash})
	if err := s1.Ack(ackedHash); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := d1.Close(); err != nil {
		t.Fatalf("close ds: %v", err)
	}

	// Second lifetime: reopen the same directory.
	d2, err := leveldbds.NewDatastore(dir, nil)
	if err != nil {
		t.Fatalf("reopen ds: %v", err)
	}
	defer d2.Close()
	s2, err := NewPersistentMessageStore(d2, log)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}

	// Only the pending envelope comes back: the acknowledged one was deleted, on disk too.
	if c := s2.Count(); c != 1 {
		t.Fatalf("recovered count = %d, want 1", c)
	}
	envs, hashes := s2.Fetch(addr)
	if len(envs) != 1 || hashes[0] != pendingHash {
		t.Fatalf("fetch after restart = %d envelopes (hashes %v), want 1 pending", len(envs), hashes)
	}
	if envs[0].MessageID != pendingEnv.MessageID {
		t.Fatal("recovered envelope payload does not match the stored one")
	}
	if n := countKeys(t, d2); n != 1 {
		t.Fatalf("datastore holds %d entries after restart, want 1", n)
	}
}

func countKeys(t *testing.T, d ds.Datastore) int {
	t.Helper()
	res, err := d.Query(context.Background(), dsquery.Query{Prefix: relayStorePrefix, KeysOnly: true})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	all, err := res.Rest()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return len(all)
}

// The queue time survives a restart, so a restart does not reset how long mail has waited.
func TestMessageStoreKeepsQueueTimeAcrossRestart(t *testing.T) {
	d := dssync.MutexWrap(ds.NewMapDatastore())
	log := logr.With(logr.M("test", true))
	queued := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	s1, err := NewPersistentMessageStore(d, log)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s1.now = func() time.Time { return queued }
	s1.Store("aa", testEnvelope(t), [32]byte{1})

	s2, err := NewPersistentMessageStore(d, log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	q := s2.Queued("aa")
	if len(q) != 1 || !q[0].StoredAt.Equal(queued) {
		t.Fatalf("queued after restart = %+v, want one entry queued at %s", q, queued)
	}
}

// Entries an older version wrote — keyed by hash alone, acknowledged ones kept with a status —
// are cleaned up on open: the delivered one is deleted, the pending one moves to its
// per-recipient key and counts as queued from now.
func TestMessageStoreUpgradesOldEntries(t *testing.T) {
	d := dssync.MutexWrap(ds.NewMapDatastore())
	log := logr.With(logr.M("test", true))
	ctx := context.Background()

	put := func(addr string, hash [32]byte, status int) {
		envBytes, err := proto.Marshal(testEnvelope(t).ToProto())
		if err != nil {
			t.Fatal(err)
		}
		val, _ := json.Marshal(map[string]any{"addr": addr, "hash": hash[:], "status": status, "env": envBytes})
		key := ds.NewKey(relayStorePrefix + "/" + hex.EncodeToString(hash[:]))
		if err := d.Put(ctx, key, val); err != nil {
			t.Fatal(err)
		}
	}
	put("aa", [32]byte{1}, 0)               // pending
	put("aa", [32]byte{2}, legacyDelivered) // acknowledged, kept by the old store

	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	s := &MessageStore{byAddr: map[string][]*storedEnvelope{}, byHash: map[[32]byte][]*storedEnvelope{}, now: func() time.Time { return now }, ds: d, log: log}
	if err := s.load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	q := s.Queued("aa")
	if len(q) != 1 || q[0].Hash != [32]byte{1} || !q[0].StoredAt.Equal(now) {
		t.Fatalf("queued = %+v, want only the pending envelope, queued from now", q)
	}
	if ok, _ := d.Has(ctx, relayStoreKey("aa", [32]byte{1})); !ok {
		t.Fatal("pending entry was not rewritten under its per-recipient key")
	}
	if n := countKeys(t, d); n != 1 {
		t.Fatalf("datastore holds %d entries, want 1 (old keys and the delivered entry removed)", n)
	}
}

// One envelope queued for two recipients on this relay is two copies: delivering one leaves the
// other queued, on disk too, and a protocol ACK — which names only the envelope — deletes only the
// copies FETCH has handed out.
func TestMessageStoreKeepsEachRecipientsCopy(t *testing.T) {
	d := dssync.MutexWrap(ds.NewMapDatastore())
	log := logr.With(logr.M("test", true))
	s, err := NewPersistentMessageStore(d, log)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	env, h := testEnvelope(t), [32]byte{7}
	s.Store("aa", env, h)
	s.Store("bb", env, h)
	s.Store("bb", env, h) // a retried STORE queues nothing new
	if c := s.Count(); c != 2 {
		t.Fatalf("count = %d, want 2", c)
	}
	if n := countKeys(t, d); n != 2 {
		t.Fatalf("datastore holds %d entries, want one per recipient", n)
	}

	if err := s.Remove("aa", h); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if q := s.Queued("bb"); len(q) != 1 {
		t.Fatalf("bb's copy went with aa's: %d queued", len(q))
	}

	// aa fetches and acknowledges; bb has not fetched, so its copy must survive the ACK.
	s.Store("aa", env, h)
	s.Fetch("aa") // a FETCH whose response never went out marks nothing
	if err := s.Ack(h); err != ErrEnvelopeNotFound {
		t.Fatalf("ack before any delivered fetch = %v, want ErrEnvelopeNotFound", err)
	}
	s.MarkFetched("aa", [][32]byte{h})
	if err := s.Ack(h); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if q := s.Queued("aa"); len(q) != 0 {
		t.Fatal("aa's acknowledged copy is still queued")
	}
	if q := s.Queued("bb"); len(q) != 1 {
		t.Fatal("an ACK deleted a copy its recipient had not fetched")
	}
	if n := countKeys(t, d); n != 1 {
		t.Fatalf("datastore holds %d entries after ack, want 1", n)
	}
}

// Expire drops what has waited past the cutoff for its address.
func TestMessageStoreExpire(t *testing.T) {
	s := NewMessageStore()
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return start }
	s.Store("old", testEnvelope(t), [32]byte{1})
	s.Store("patient", testEnvelope(t), [32]byte{2})
	s.now = func() time.Time { return start.Add(3 * 24 * time.Hour) }
	s.Store("new", testEnvelope(t), [32]byte{3})

	n := s.Expire(func(addr string) time.Time {
		if addr == "patient" {
			return start
		}
		return start.Add(24 * time.Hour)
	})
	if n != 1 {
		t.Fatalf("expired %d, want 1", n)
	}
	if q := s.Queued("old"); len(q) != 0 {
		t.Fatal("the old envelope survived its lifetime")
	}
	if q := s.Queued("patient"); len(q) != 1 {
		t.Fatal("an envelope inside its address's longer lifetime was expired")
	}
	if q := s.Queued("new"); len(q) != 1 {
		t.Fatal("an envelope inside its lifetime was expired")
	}
}

// A failed rewrite of an old-format entry leaves the old key in place for the next start, rather
// than deleting the only copy on disk.
func TestMessageStoreUpgradeKeepsOldEntryWhenRewriteFails(t *testing.T) {
	inner := dssync.MutexWrap(ds.NewMapDatastore())
	ctx := context.Background()
	hash := [32]byte{1}
	envBytes, err := proto.Marshal(testEnvelope(t).ToProto())
	if err != nil {
		t.Fatal(err)
	}
	val, _ := json.Marshal(map[string]any{"addr": "aa", "hash": hash[:], "env": envBytes})
	oldKey := ds.NewKey(relayStorePrefix + "/" + hex.EncodeToString(hash[:]))
	if err := inner.Put(ctx, oldKey, val); err != nil {
		t.Fatal(err)
	}

	d := failingPuts{inner}
	s, err := NewPersistentMessageStore(d, logr.With(logr.M("test", true)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if q := s.Queued("aa"); len(q) != 1 {
		t.Fatal("the pending envelope was not loaded")
	}
	if ok, _ := inner.Has(ctx, oldKey); !ok {
		t.Fatal("the old-format entry was deleted although its rewrite failed")
	}
}

// An old-format key whose delete failed last time sits beside its rewritten entry. The rewritten
// entry's queue time wins, and the old key is deleted, instead of the old key being loaded as
// "queued now" on every restart and never expiring.
func TestMessageStoreUpgradeLeftoverKeepsQueueTime(t *testing.T) {
	d := dssync.MutexWrap(ds.NewMapDatastore())
	ctx := context.Background()
	hash := [32]byte{1}
	queued := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	envBytes, err := proto.Marshal(testEnvelope(t).ToProto())
	if err != nil {
		t.Fatal(err)
	}
	oldVal, _ := json.Marshal(map[string]any{"addr": "aa", "hash": hash[:], "env": envBytes})
	newVal, _ := json.Marshal(persistedEnvelope{Addr: "aa", Hash: hash[:], StoredAt: queued.Unix(), Env: envBytes})
	oldKey := ds.NewKey(relayStorePrefix + "/" + hex.EncodeToString(hash[:]))
	if err := d.Put(ctx, oldKey, oldVal); err != nil {
		t.Fatal(err)
	}
	if err := d.Put(ctx, relayStoreKey("aa", hash), newVal); err != nil {
		t.Fatal(err)
	}

	s, err := NewPersistentMessageStore(d, logr.With(logr.M("test", true)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if q := s.Queued("aa"); len(q) != 1 || !q[0].StoredAt.Equal(queued) {
		t.Fatalf("queued = %+v, want one entry keeping its queue time %s", q, queued)
	}
	if ok, _ := d.Has(ctx, oldKey); ok {
		t.Fatal("the leftover old-format key was not deleted")
	}
}

// failingPuts is a datastore whose writes all fail.
type failingPuts struct{ ds.Batching }

func (failingPuts) Put(context.Context, ds.Key, []byte) error { return errors.New("disk full") }

// In-memory stores (no datastore) keep working unchanged — persist is a no-op.
func TestInMemoryStoreUnaffected(t *testing.T) {
	s := NewMessageStore()
	env := testEnvelope(t)
	h := [32]byte{9}
	s.Store("aa", env, h)
	if c := s.Count(); c != 1 {
		t.Fatalf("count = %d, want 1", c)
	}
	if envs, _ := s.Fetch("aa"); len(envs) != 1 {
		t.Fatalf("fetch = %d, want 1", len(envs))
	}
}

// A copy stored again between being taken out of the maps and being deleted from disk — a
// retried STORE racing a Remove, Ack or Expire — keeps its entry on disk.
func TestMessageStoreDeleteKeepsACopyStoredAgain(t *testing.T) {
	d := dssync.MutexWrap(ds.NewMapDatastore())
	s, err := NewPersistentMessageStore(d, logr.With(logr.M("test", true)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	env, h := testEnvelope(t), [32]byte{3}
	s.Store("aa", env, h)

	// Remove's first half: out of the maps, lock released, disk delete still to come.
	s.mu.Lock()
	se := s.find("aa", h)
	s.unindex(se)
	s.mu.Unlock()
	s.Store("aa", env, h) // the racing STORE
	s.deleteCopies([]*storedEnvelope{se})

	if q := s.Queued("aa"); len(q) != 1 {
		t.Fatal("the copy stored again is not queued")
	}
	if ok, _ := d.Has(context.Background(), relayStoreKey("aa", h)); !ok {
		t.Fatal("the late delete removed the copy stored again from disk")
	}
}

// The fetched mark survives a restart: an ACK for mail handed out before the relay restarted
// still deletes it, instead of finding nothing and leaving it to be delivered again. The mark is
// its own small entry, and goes with its copy.
func TestMessageStoreFetchedMarkSurvivesRestart(t *testing.T) {
	d := dssync.MutexWrap(ds.NewMapDatastore())
	log := logr.With(logr.M("test", true))
	s1, err := NewPersistentMessageStore(d, log)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	h := [32]byte{4}
	s1.Store("aa", testEnvelope(t), h)
	s1.MarkFetched("aa", [][32]byte{h})
	if ok, _ := d.Has(context.Background(), relayFetchedKey("aa", h)); !ok {
		t.Fatal("the fetched mark was not written")
	}

	s2, err := NewPersistentMessageStore(d, log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := s2.Ack(h); err != nil {
		t.Fatalf("ack after restart: %v", err)
	}
	if q := s2.Queued("aa"); len(q) != 0 {
		t.Fatal("the acknowledged copy is still queued")
	}
	if ok, _ := d.Has(context.Background(), relayFetchedKey("aa", h)); ok {
		t.Fatal("the fetched mark outlived its copy")
	}
}
