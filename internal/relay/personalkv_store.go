package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"
)

// personalKvPrefix namespaces the owner-only personal key-value store, keyed by
// the owner's X25519 public key (hex) — the same rxHex mailboxes use. Under it,
// each blob lives at a client-chosen logical key "<namespace>/<id>":
//
//	/dmcn/personalkv/<ownerHex>/sent/<messageIdHex>
//	/dmcn/personalkv/<ownerHex>/flags/<messageHash>
//	/dmcn/personalkv/<ownerHex>/contacts/<id>
//	/dmcn/personalkv/<ownerHex>/settings/app
//
// Values are message.SealedBlob JSON sealed to the OWNER alone, so the relay only
// ever holds ciphertext (unlike the mail filter, which is also sealed to the relay
// so it can enforce it at STORE). This is the zero-knowledge storage substrate
// behind Sent, read/unread+labels, contacts and settings.
const personalKvPrefix = "/dmcn/personalkv"

// ErrKvConflict is returned by Put when a compare-and-swap (expectedVersion != 0)
// does not match the stored version — the caller should re-read and retry.
var ErrKvConflict = errors.New("relay: personal kv version conflict")

// ErrKvBadKey is returned for a malformed or namespace-escaping logical key.
var ErrKvBadKey = errors.New("relay: personal kv invalid key")

// PersistentKvStore is the owner-only personal KV store over the node's (borrowed)
// datastore. Every op is scoped to ownerHex, which the relay derives from the
// FETCH-authenticated caller — so ownership is enforced by the auth layer, not by
// anything the client sends.
type PersistentKvStore struct {
	store ds.Batching
	mu    sync.Mutex // serializes read-modify-write in Put so local CAS is race-free
	// now stamps each write. The time is the relay's observation and never the writer's claim,
	// which is the point of recording it. Overridable in tests.
	now func() time.Time
}

// SetClock overrides the write clock. Tests only.
func (s *PersistentKvStore) SetClock(now func() time.Time) { s.now = now }

// NewPersonalKvStore returns a personal KV store over the given datastore.
func NewPersonalKvStore(d ds.Batching) *PersistentKvStore {
	return &PersistentKvStore{store: d, now: time.Now}
}

// KvItem is one entry in a KV list page. Sealed is populated only when the list
// requested values.
type KvItem struct {
	Key     string
	Sealed  []byte
	Version uint64
	// WrittenAt is this relay's clock, in Unix seconds, when the version was written. 0 on an
	// entry written before the relay recorded it.
	WrittenAt int64
	// SealedWriter names the device that signed the write, sealed to the owner (see Relay.KvPut).
	// Empty where the write carried no device proof.
	SealedWriter []byte
}

// kvRecord is the stored wrapper: an opaque sealed blob plus a monotonic version
// used for compare-and-swap. The relay never interprets Sealed.
type kvRecord struct {
	Version   uint64 `json:"version"`
	Sealed    []byte `json:"sealed"`
	WrittenAt int64  `json:"written_at,omitempty"`
	Writer    []byte `json:"writer,omitempty"`
}

func ownerPrefix(ownerHex string) string {
	return fmt.Sprintf("%s/%s", personalKvPrefix, ownerHex)
}

// validKvKey guards the client-chosen logical key: non-empty, bounded, no leading/
// trailing slash, and no empty/"."/".." path segments (which datastore path cleaning
// could otherwise use to escape the owner's namespace). Restricted to a safe charset.
func validKvKey(key string) bool {
	if key == "" || len(key) > 512 {
		return false
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == '/':
		default:
			return false
		}
	}
	return true
}

// kvKey builds the datastore key for an owner's logical key and verifies path
// cleaning did not let it escape the owner namespace (defense in depth).
func kvKey(ownerHex, key string) (ds.Key, error) {
	if !validKvKey(key) {
		return ds.Key{}, ErrKvBadKey
	}
	op := ownerPrefix(ownerHex)
	k := ds.NewKey(fmt.Sprintf("%s/%s", op, key))
	if !strings.HasPrefix(k.String()+"/", op+"/") {
		return ds.Key{}, ErrKvBadKey
	}
	return k, nil
}

// Get returns the sealed blob + version for a key, or found=false if absent.
func (s *PersistentKvStore) Get(ctx context.Context, ownerHex, key string) (sealed []byte, version uint64, found bool, err error) {
	it, found, err := s.GetEntry(ctx, ownerHex, key)
	return it.Sealed, it.Version, found, err
}

// GetEntry returns one entry with the marks the relay keeps beside it, or found=false.
func (s *PersistentKvStore) GetEntry(ctx context.Context, ownerHex, key string) (item KvItem, found bool, err error) {
	k, err := kvKey(ownerHex, key)
	if err != nil {
		return KvItem{}, false, err
	}
	data, err := s.store.Get(ctx, k)
	if errors.Is(err, ds.ErrNotFound) {
		return KvItem{}, false, nil
	}
	if err != nil {
		return KvItem{}, false, fmt.Errorf("relay: personal kv get: %w", err)
	}
	var rec kvRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return KvItem{}, false, fmt.Errorf("relay: personal kv unmarshal: %w", err)
	}
	return KvItem{Key: key, Sealed: rec.Sealed, Version: rec.Version, WrittenAt: rec.WrittenAt, SealedWriter: rec.Writer}, true, nil
}

// Put writes (creates or overwrites) a blob and returns the new version. When
// expectedVersion != 0 the write is a compare-and-swap: it succeeds only if the
// stored version equals expectedVersion, else it returns ErrKvConflict.
func (s *PersistentKvStore) Put(ctx context.Context, ownerHex, key string, sealed []byte, expectedVersion uint64) (newVersion uint64, err error) {
	return s.PutBy(ctx, ownerHex, key, sealed, expectedVersion, nil)
}

// PutBy is Put with the writing device recorded beside the entry. sealedWriter is opaque here:
// the caller sealed it to the owner. Every write is stamped with this store's clock.
func (s *PersistentKvStore) PutBy(ctx context.Context, ownerHex, key string, sealed []byte, expectedVersion uint64, sealedWriter []byte) (newVersion uint64, err error) {
	k, err := kvKey(ownerHex, key)
	if err != nil {
		return 0, err
	}
	if len(sealed) == 0 {
		return 0, fmt.Errorf("relay: personal kv put: empty blob")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cur := uint64(0)
	data, gErr := s.store.Get(ctx, k)
	switch {
	case gErr == nil:
		var rec kvRecord
		if json.Unmarshal(data, &rec) == nil {
			cur = rec.Version
		}
	case errors.Is(gErr, ds.ErrNotFound):
		// key absent → cur stays 0
	default:
		return 0, fmt.Errorf("relay: personal kv put: read: %w", gErr)
	}

	if expectedVersion != 0 && cur != expectedVersion {
		return 0, ErrKvConflict
	}

	newVersion = cur + 1
	out, err := json.Marshal(kvRecord{Version: newVersion, Sealed: sealed, WrittenAt: s.now().Unix(), Writer: sealedWriter})
	if err != nil {
		return 0, fmt.Errorf("relay: personal kv put: marshal: %w", err)
	}
	if err := s.store.Put(ctx, k, out); err != nil {
		return 0, fmt.Errorf("relay: personal kv put: %w", err)
	}
	return newVersion, nil
}

// Inject writes a blob at an exact version, unconditionally — used by the drain
// handoff to move a record to a new home relay while preserving its version. Unlike
// Put it does not bump the version or compare-and-swap.
func (s *PersistentKvStore) Inject(ctx context.Context, ownerHex, key string, sealed []byte, version uint64) error {
	k, err := kvKey(ownerHex, key)
	if err != nil {
		return err
	}
	if len(sealed) == 0 {
		return fmt.Errorf("relay: personal kv inject: empty blob")
	}
	out, err := json.Marshal(kvRecord{Version: version, Sealed: sealed})
	if err != nil {
		return fmt.Errorf("relay: personal kv inject: marshal: %w", err)
	}
	if err := s.store.Put(ctx, k, out); err != nil {
		return fmt.Errorf("relay: personal kv inject: %w", err)
	}
	return nil
}

// Delete removes a blob by key. Idempotent: deleting an absent key is not an error.
func (s *PersistentKvStore) Delete(ctx context.Context, ownerHex, key string) error {
	k, err := kvKey(ownerHex, key)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, k); err != nil {
		return fmt.Errorf("relay: personal kv delete: %w", err)
	}
	return nil
}

// List returns up to limit blobs whose logical key starts with prefix (e.g.
// "sent/"), in sorted key order, starting strictly after cursor. nextCursor is the
// continuation cursor, or empty when fully listed. When values is false only keys
// are returned (Sealed nil, Version 0).
func (s *PersistentKvStore) List(ctx context.Context, ownerHex, prefix string, limit int, cursor string, values bool) (items []KvItem, nextCursor string, err error) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	op := ownerPrefix(ownerHex)
	qprefix := op
	if prefix != "" {
		p := strings.TrimSuffix(prefix, "/")
		if !validKvKey(p) {
			return nil, "", ErrKvBadKey
		}
		qprefix = op + "/" + p
	}

	res, err := s.store.Query(ctx, dsquery.Query{Prefix: qprefix, KeysOnly: !values})
	if err != nil {
		return nil, "", fmt.Errorf("relay: personal kv list: query: %w", err)
	}
	defer res.Close()

	lastKey := ""
	for r := range res.Next() {
		if r.Error != nil {
			return nil, "", fmt.Errorf("relay: personal kv list: %w", r.Error)
		}
		if cursor != "" && r.Key <= cursor {
			continue
		}
		logical := strings.TrimPrefix(r.Key, op+"/")
		if logical == r.Key {
			continue // not under this owner (shouldn't happen given the prefix)
		}
		// Namespace-boundary guard: a range scan on "sent" would also see a
		// hypothetical "sentinel/" key; the client's prefix ("sent/") excludes it.
		if prefix != "" && !strings.HasPrefix(logical, prefix) {
			continue
		}
		it := KvItem{Key: logical}
		if values {
			var rec kvRecord
			if err := json.Unmarshal(r.Value, &rec); err != nil {
				continue // skip a corrupt entry rather than failing the page
			}
			it.Sealed = rec.Sealed
			it.Version = rec.Version
			it.WrittenAt = rec.WrittenAt
			it.SealedWriter = rec.Writer
		}
		items = append(items, it)
		lastKey = r.Key
		if len(items) >= limit {
			break
		}
	}

	if len(items) == limit {
		nextCursor = lastKey
	}
	return items, nextCursor, nil
}

// StatsOwner reports the blob count + stored bytes for one owner (for per-owner
// quota accounting). Bytes counts the stored record (sealed ciphertext + version
// wrapper), which is what the datastore actually holds.
func (s *PersistentKvStore) StatsOwner(ctx context.Context, ownerHex string) (count, bytes uint64, err error) {
	return s.statsPrefix(ctx, ownerPrefix(ownerHex))
}

// Stats reports the global blob count + bytes across all owners, for STAT.
func (s *PersistentKvStore) Stats(ctx context.Context) (count, bytes uint64, err error) {
	return s.statsPrefix(ctx, personalKvPrefix)
}

func (s *PersistentKvStore) statsPrefix(ctx context.Context, prefix string) (count, bytes uint64, err error) {
	res, err := s.store.Query(ctx, dsquery.Query{Prefix: prefix})
	if err != nil {
		return 0, 0, fmt.Errorf("relay: personal kv stats: query: %w", err)
	}
	defer res.Close()
	for r := range res.Next() {
		if r.Error != nil {
			return 0, 0, fmt.Errorf("relay: personal kv stats: %w", r.Error)
		}
		count++
		bytes += uint64(len(r.Value))
	}
	return count, bytes, nil
}
