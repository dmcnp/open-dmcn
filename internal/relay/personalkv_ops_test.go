package relay

import (
	"context"
	"errors"
	"strings"
	"testing"

	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	"github.com/mertenvg/logr/v2"
)

// personalkv_ops_test.go covers the Relay-level personal-storage operations — the ones both the
// libp2p stream handler and the daemon's in-process webmail call, so that quota and error
// handling cannot differ between the two transports.

func kvRelay(t *testing.T, quota uint64) *Relay {
	t.Helper()
	store := dssync.MutexWrap(ds.NewMapDatastore())
	return &Relay{
		personalKv:   NewPersonalKvStore(store),
		storageQuota: quota,
		log:          logr.With(logr.M("test", "personalkv")),
	}
}

const kvOwner = "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990"

// TestKvRoundTrip is the basic contract: what goes in comes out, versions advance, and a list
// sees it.
func TestKvRoundTrip(t *testing.T) {
	r := kvRelay(t, 0)
	ctx := context.Background()

	v1, err := r.KvPut(ctx, kvOwner, "contacts/alice", []byte("sealed-blob-1"), 0)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	sealed, version, found, err := r.KvGet(ctx, kvOwner, "contacts/alice")
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if string(sealed) != "sealed-blob-1" || version != v1 {
		t.Errorf("got %q v%d, want the stored blob at v%d", sealed, version, v1)
	}

	items, _, err := r.KvList(ctx, kvOwner, "contacts/", 0, "", true)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 1 || items[0].Key != "contacts/alice" {
		t.Fatalf("list returned %+v", items)
	}

	if err := r.KvDelete(ctx, kvOwner, "contacts/alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, found, _ = r.KvGet(ctx, kvOwner, "contacts/alice"); found {
		t.Error("the key survived deletion")
	}
}

// TestKvIsolatedPerOwner is the one that would be a privacy breach rather than a bug: the store
// is keyed by mailbox, and one owner must never see another's namespace.
func TestKvIsolatedPerOwner(t *testing.T) {
	r := kvRelay(t, 0)
	ctx := context.Background()
	other := strings.Repeat("bb", 32)

	if _, err := r.KvPut(ctx, kvOwner, "contacts/alice", []byte("mine"), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := r.KvGet(ctx, other, "contacts/alice"); found {
		t.Fatal("one owner read another owner's key")
	}
	items, _, err := r.KvList(ctx, other, "contacts/", 0, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("another owner's namespace listed %d item(s)", len(items))
	}
}

// TestKvCompareAndSwap covers the case the version exists for: the same singleton document edited
// on two devices. The second writer must be told rather than silently winning.
func TestKvCompareAndSwap(t *testing.T) {
	r := kvRelay(t, 0)
	ctx := context.Background()

	v1, err := r.KvPut(ctx, kvOwner, "settings/app", []byte("a"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.KvPut(ctx, kvOwner, "settings/app", []byte("b"), v1); err != nil {
		t.Fatalf("CAS at the current version was rejected: %v", err)
	}
	// A second device still holding v1 must lose.
	if _, err := r.KvPut(ctx, kvOwner, "settings/app", []byte("c"), v1); !errors.Is(err, ErrKvConflict) {
		t.Errorf("a stale CAS was accepted: %v", err)
	}
	// Unconditional writes still overwrite — that is what expectedVersion=0 means.
	if _, err := r.KvPut(ctx, kvOwner, "settings/app", []byte("d"), 0); err != nil {
		t.Errorf("unconditional write rejected: %v", err)
	}
}

// TestKvQuotaIsEnforced pins that the cap applies on the storage path, not only to mail.
func TestKvQuotaIsEnforced(t *testing.T) {
	r := kvRelay(t, 64)
	ctx := context.Background()

	if _, err := r.KvPut(ctx, kvOwner, "contacts/a", make([]byte, 32), 0); err != nil {
		t.Fatalf("a write within quota was refused: %v", err)
	}
	if _, err := r.KvPut(ctx, kvOwner, "contacts/b", make([]byte, 128), 0); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("a write over quota was accepted: %v", err)
	}
}

// TestKvStatReportsTheEnforcedFigure keeps the usage meter honest. It must report the same total
// the quota is checked against, or someone sees free space while writes are being refused.
func TestKvStatReportsTheEnforcedFigure(t *testing.T) {
	r := kvRelay(t, 1024)
	ctx := context.Background()
	if _, err := r.KvPut(ctx, kvOwner, "contacts/a", make([]byte, 100), 0); err != nil {
		t.Fatal(err)
	}
	used, quota, count, err := r.KvStat(ctx, kvOwner)
	if err != nil {
		t.Fatal(err)
	}
	if quota != 1024 {
		t.Errorf("quota = %d, want the node cap", quota)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	if used < 100 {
		t.Errorf("used = %d, want at least the blob size", used)
	}
}

// TestKvUnsupportedWhenAbsent is what lets a minimal relay serve mail without storage: the error
// is specific, so a client can fall back to local state instead of treating the mailbox as broken.
func TestKvUnsupportedWhenAbsent(t *testing.T) {
	r := &Relay{log: logr.With(logr.M("test", "personalkv"))} // no personalKv
	ctx := context.Background()

	if _, _, _, err := r.KvGet(ctx, kvOwner, "contacts/a"); !errors.Is(err, ErrKvUnsupported) {
		t.Errorf("get: %v", err)
	}
	if _, err := r.KvPut(ctx, kvOwner, "contacts/a", []byte("x"), 0); !errors.Is(err, ErrKvUnsupported) {
		t.Errorf("put: %v", err)
	}
	if _, _, err := r.KvList(ctx, kvOwner, "contacts/", 0, "", true); !errors.Is(err, ErrKvUnsupported) {
		t.Errorf("list: %v", err)
	}
	if err := r.KvDelete(ctx, kvOwner, "contacts/a"); !errors.Is(err, ErrKvUnsupported) {
		t.Errorf("delete: %v", err)
	}
	if _, _, _, err := r.KvStat(ctx, kvOwner); !errors.Is(err, ErrKvUnsupported) {
		t.Errorf("stat: %v", err)
	}
}

// TestKvDeleteIsIdempotent: a client removing something that is already gone has got what it
// wanted, and a malformed key cannot name anything that exists.
func TestKvDeleteIsIdempotent(t *testing.T) {
	r := kvRelay(t, 0)
	ctx := context.Background()
	if err := r.KvDelete(ctx, kvOwner, "contacts/never-existed"); err != nil {
		t.Errorf("deleting an absent key errored: %v", err)
	}
	if err := r.KvDelete(ctx, kvOwner, "../escape"); err != nil {
		t.Errorf("deleting a malformed key errored instead of being a no-op: %v", err)
	}
}
