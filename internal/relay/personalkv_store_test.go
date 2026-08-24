package relay

import (
	"context"
	"errors"
	"testing"
)

// TestPersonalKvRoundTrip covers Put/Get/List/Delete plus per-owner scoping.
func TestPersonalKvRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	kv := NewPersonalKvStore(d)

	owner := "aa" + "00" // arbitrary owner hex id
	other := "bb" + "11"

	// Absent key → not found.
	if _, _, found, err := kv.Get(ctx, owner, "sent/1"); err != nil || found {
		t.Fatalf("get absent: found=%v err=%v", found, err)
	}

	// Put → version 1.
	v, err := kv.Put(ctx, owner, "sent/1", []byte(`{"blob":"a"}`), 0)
	if err != nil || v != 1 {
		t.Fatalf("put: v=%d err=%v", v, err)
	}
	// Get returns the blob + version.
	sealed, ver, found, err := kv.Get(ctx, owner, "sent/1")
	if err != nil || !found || ver != 1 || string(sealed) != `{"blob":"a"}` {
		t.Fatalf("get: sealed=%s ver=%d found=%v err=%v", sealed, ver, found, err)
	}
	// Overwrite bumps the version.
	if v, err := kv.Put(ctx, owner, "sent/1", []byte(`{"blob":"b"}`), 0); err != nil || v != 2 {
		t.Fatalf("overwrite: v=%d err=%v", v, err)
	}

	// Owner scoping: the other owner cannot see it.
	if _, _, found, _ := kv.Get(ctx, other, "sent/1"); found {
		t.Fatal("cross-owner get should not find another owner's key")
	}

	// Delete is idempotent.
	if err := kv.Delete(ctx, owner, "sent/1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := kv.Delete(ctx, owner, "sent/1"); err != nil {
		t.Fatalf("delete idempotent: %v", err)
	}
	if _, _, found, _ := kv.Get(ctx, owner, "sent/1"); found {
		t.Fatal("get after delete should not find")
	}
}

// TestPersonalKvListPaging verifies namespace-scoped listing + cursor paging.
func TestPersonalKvListPaging(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	kv := NewPersonalKvStore(d)
	owner := "cc22"

	// Two namespaces; only "sent/" should come back for that prefix.
	for _, k := range []string{"sent/a", "sent/b", "sent/c", "flags/x", "flags/y"} {
		if _, err := kv.Put(ctx, owner, k, []byte(`{"k":"`+k+`"}`), 0); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}

	// Page size 2 → two pages then a final partial page with no cursor.
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		items, next, err := kv.List(ctx, owner, "sent/", 2, cursor, true)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		pages++
		for _, it := range items {
			seen[it.Key] = true
			if len(it.Sealed) == 0 || it.Version == 0 {
				t.Fatalf("list item missing value/version: %+v", it)
			}
		}
		if next == "" {
			break
		}
		cursor = next
		if pages > 10 {
			t.Fatal("paging did not terminate")
		}
	}
	for _, want := range []string{"sent/a", "sent/b", "sent/c"} {
		if !seen[want] {
			t.Fatalf("missing %s from sent/ listing: %v", want, seen)
		}
	}
	if seen["flags/x"] || seen["flags/y"] {
		t.Fatalf("sent/ listing leaked flags namespace: %v", seen)
	}

	// values=false omits the blob.
	items, _, err := kv.List(ctx, owner, "flags/", 0, "", false)
	if err != nil || len(items) != 2 {
		t.Fatalf("flags list: n=%d err=%v", len(items), err)
	}
	for _, it := range items {
		if len(it.Sealed) != 0 {
			t.Fatalf("values=false should omit sealed: %+v", it)
		}
	}
}

// TestPersonalKvCAS covers compare-and-swap conflict semantics.
func TestPersonalKvCAS(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	kv := NewPersonalKvStore(d)
	owner := "dd33"

	// Create at v1.
	if _, err := kv.Put(ctx, owner, "settings/app", []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("create: %v", err)
	}
	// CAS with stale expected version → conflict.
	if _, err := kv.Put(ctx, owner, "settings/app", []byte(`{"n":2}`), 99); !errors.Is(err, ErrKvConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	// CAS with correct expected version → succeeds, bumps to v2.
	v, err := kv.Put(ctx, owner, "settings/app", []byte(`{"n":2}`), 1)
	if err != nil || v != 2 {
		t.Fatalf("cas ok: v=%d err=%v", v, err)
	}
}

// TestPersonalKvStatsAndQuota covers per-owner byte accounting.
func TestPersonalKvStatsOwner(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	kv := NewPersonalKvStore(d)
	owner := "ee44"

	if c, b, err := kv.StatsOwner(ctx, owner); err != nil || c != 0 || b != 0 {
		t.Fatalf("empty stats: c=%d b=%d err=%v", c, b, err)
	}
	if _, err := kv.Put(ctx, owner, "sent/1", []byte(`{"x":"aaaa"}`), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, owner, "sent/2", []byte(`{"x":"bbbb"}`), 0); err != nil {
		t.Fatal(err)
	}
	c, b, err := kv.StatsOwner(ctx, owner)
	if err != nil || c != 2 || b == 0 {
		t.Fatalf("stats after 2 puts: c=%d b=%d err=%v", c, b, err)
	}
}

// TestPersonalKvBadKey rejects malformed / namespace-escaping keys.
func TestPersonalKvBadKey(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	kv := NewPersonalKvStore(d)
	owner := "ff55"

	for _, bad := range []string{"", "/abs", "trailing/", "a//b", "a/../b", "../escape", "bad key", "nul\x00"} {
		if _, err := kv.Put(ctx, owner, bad, []byte(`{}`), 0); !errors.Is(err, ErrKvBadKey) {
			t.Fatalf("expected ErrKvBadKey for %q, got %v", bad, err)
		}
	}
	// A valid multi-segment key is accepted.
	if _, err := kv.Put(ctx, owner, "contacts/abc-123_x.y", []byte(`{}`), 0); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

// TestKvDeleteMissingKeyIsNoOp pins that deleting a key that was never written succeeds.
//
// Legacy Sent rows (written before Sent moved to storing the sealed envelope) have a
// "sent/<id>" entry but no "sent-body/<id>" one, and deleting such a row issues both
// deletes. An error on the missing half would surface as a failed delete on exactly the
// old messages the folder just started showing again.
func TestKvDeleteMissingKeyIsNoOp(t *testing.T) {
	ctx := context.Background()
	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	kv := NewPersonalKvStore(d)

	if err := kv.Delete(ctx, "aa00", "sent-body/never-written"); err != nil {
		t.Fatalf("deleting a missing key returned %v, want nil", err)
	}
}
