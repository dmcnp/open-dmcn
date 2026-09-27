// Package relay implements the DMCN relay node protocol for message
// storage and delivery. See SPEC.md §5.
package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"
	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// relayStorePrefix namespaces durable relay-store keys in a (possibly shared)
// datastore. Each queued copy is one key: /dmcn/relaystore/<hashHex>/<recipient>.
const relayStorePrefix = "/dmcn/relaystore"

// relayStoreKey names one recipient's copy of an envelope. The recipient is part of the key
// because one envelope can be queued here for several recipients, and each is delivered — and
// deleted — on its own.
func relayStoreKey(addr string, hash [32]byte) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s/%s", relayStorePrefix, hex.EncodeToString(hash[:]), addr))
}

// relayFetchedPrefix holds one small marker per copy a FETCH has handed out, beside the copy's own
// entry rather than in it, so marking a copy never rewrites the envelope:
// /dmcn/relayfetched/<hashHex>/<recipient>.
const relayFetchedPrefix = "/dmcn/relayfetched"

func relayFetchedKey(addr string, hash [32]byte) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s/%s", relayFetchedPrefix, hex.EncodeToString(hash[:]), addr))
}

// persistedEnvelope is the on-disk form of a storedEnvelope. The envelope itself
// is stored as deterministic protobuf; the JSON wrapper carries the routing
// address and queue time that the in-memory index needs to rebuild on open.
type persistedEnvelope struct {
	Addr     string `json:"addr"`
	Hash     []byte `json:"hash"`
	StoredAt int64  `json:"storedAt,omitempty"` // Unix seconds; absent on entries written before it existed
	// Status is read only from entries written before an ACK deleted the envelope: 1 meant
	// delivered, and such an entry is dropped on load. New entries never set it.
	Status int    `json:"status,omitempty"`
	Env    []byte `json:"env"`
}

// legacyDelivered is the Status an old entry carried once it had been acknowledged.
const legacyDelivered = 1

var (
	// ErrEnvelopeNotFound is returned when an envelope hash is not in the store.
	ErrEnvelopeNotFound = errors.New("relay: envelope not found")
)

// storedEnvelope is one recipient's queued copy of an envelope.
type storedEnvelope struct {
	Envelope *message.EncryptedEnvelope
	Hash     [32]byte
	Addr     string
	StoredAt time.Time
	// Fetched is set once an authenticated FETCH has handed this copy out (MarkFetched); only such
	// a copy can be acknowledged. Persisted as a marker under relayFetchedPrefix, so an ACK that
	// arrives after a restart still finds it.
	Fetched bool
}

// QueuedEnvelope is an envelope waiting in the store, with the time it was queued so a consumer
// can tell how long it has been waiting.
type QueuedEnvelope struct {
	Envelope *message.EncryptedEnvelope
	Hash     [32]byte
	StoredAt time.Time
}

// MessageStore holds in-flight encrypted envelopes for relay STORE/FETCH/ACK,
// indexed by recipient address. It holds only mail that has not been delivered:
// an acknowledged copy is deleted, and one nobody collects is dropped by Expire. The in-memory maps are the fast read path; when a datastore is
// configured (NewPersistentMessageStore) every mutation is also written through
// to disk and the maps are rebuilt on open, so queued mail survives a restart.
type MessageStore struct {
	mu     sync.RWMutex
	byAddr map[string][]*storedEnvelope   // recipient address → its queued copies
	byHash map[[32]byte][]*storedEnvelope // envelope hash → one copy per recipient
	count  int

	now func() time.Time // test seam
	ds  ds.Batching      // nil ⇒ in-memory only
	log logr.Logger      // used only on the persistent path
}

// NewMessageStore creates an empty in-memory message store (no persistence).
func NewMessageStore() *MessageStore {
	return &MessageStore{
		byAddr: make(map[string][]*storedEnvelope),
		byHash: make(map[[32]byte][]*storedEnvelope),
		now:    time.Now,
	}
}

// NewPersistentMessageStore creates a message store backed by a datastore. Any
// envelopes already on disk are loaded into the in-memory index, so in-flight
// mail survives a process restart.
func NewPersistentMessageStore(d ds.Batching, log logr.Logger) (*MessageStore, error) {
	s := NewMessageStore()
	s.ds = d
	s.log = log
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load rebuilds the in-memory index from the datastore. A corrupt entry is
// skipped (logged) rather than failing the whole load.
//
// It also clears up after older versions of the store, which kept acknowledged envelopes on
// disk for good and keyed each envelope by hash alone: an acknowledged entry is deleted, and a
// pending one is rewritten under its per-recipient key. An entry that predates StoredAt is
// treated as queued now, so upgrading never expires mail that is still waiting. Entries under
// the current keys are indexed first, so an old key whose delete failed last time never
// replaces the queue time its rewritten entry already carries.
func (s *MessageStore) load() error {
	ctx := context.Background()
	res, err := s.ds.Query(ctx, dsquery.Query{Prefix: relayStorePrefix})
	if err != nil {
		return fmt.Errorf("relay store: load query: %w", err)
	}

	type oldEntry struct {
		key ds.Key
		se  *storedEnvelope
	}
	var (
		old     []oldEntry // pending entries under a hash-only key, rewritten once the scan is done
		stale   []ds.Key   // keys to delete once the scan is done
		n       int
		dropped int
	)
	for r := range res.Next() {
		if r.Error != nil {
			res.Close()
			return fmt.Errorf("relay store: load: %w", r.Error)
		}
		key := ds.NewKey(r.Key)
		var pe persistedEnvelope
		if err := json.Unmarshal(r.Value, &pe); err != nil {
			s.log.Warnf("relay store: skip corrupt entry %s: %v", r.Key, err)
			continue
		}
		if pe.Status == legacyDelivered {
			stale = append(stale, key)
			dropped++
			continue
		}
		se, err := s.decode(pe)
		if err != nil {
			s.log.Warnf("relay store: skip %s: %v", r.Key, err)
			continue
		}
		if key != relayStoreKey(se.Addr, se.Hash) {
			old = append(old, oldEntry{key, se})
			continue
		}
		if s.find(se.Addr, se.Hash) == nil {
			s.index(se)
			n++
		}
	}
	res.Close()

	// An old-format key is deleted only once its entry is safely under the new one; if the
	// rewrite fails it stays, and the next start tries again.
	for _, o := range old {
		if s.find(o.se.Addr, o.se.Hash) == nil {
			s.index(o.se)
			n++
			if err := s.persist(o.se); err != nil {
				s.log.Warnf("relay store: rewrite old-format entry %s: %v", o.key, err)
				continue
			}
		}
		stale = append(stale, o.key)
	}
	s.deleteKeys(stale)
	if err := s.loadFetched(ctx); err != nil {
		return err
	}

	if dropped > 0 {
		s.log.Infof("relay store: dropped %d delivered envelope(s) kept by an older version", dropped)
	}
	if n > 0 {
		s.log.Infof("relay store: recovered %d in-flight envelope(s) from disk", n)
	}
	return nil
}

// loadFetched restores the fetched marks, deleting any marker whose copy is gone.
func (s *MessageStore) loadFetched(ctx context.Context) error {
	res, err := s.ds.Query(ctx, dsquery.Query{Prefix: relayFetchedPrefix, KeysOnly: true})
	if err != nil {
		return fmt.Errorf("relay store: load fetched marks: %w", err)
	}
	var stale []ds.Key
	for r := range res.Next() {
		if r.Error != nil {
			res.Close()
			return fmt.Errorf("relay store: load fetched marks: %w", r.Error)
		}
		key := ds.NewKey(r.Key)
		parts := key.Namespaces() // dmcn, relayfetched, <hashHex>, <recipient>
		var hash [32]byte
		if len(parts) != 4 || hex.DecodedLen(len(parts[2])) != len(hash) {
			stale = append(stale, key)
			continue
		}
		if _, err := hex.Decode(hash[:], []byte(parts[2])); err != nil {
			stale = append(stale, key)
			continue
		}
		if se := s.find(parts[3], hash); se != nil {
			se.Fetched = true
		} else {
			stale = append(stale, key)
		}
	}
	res.Close()
	s.deleteKeys(stale)
	return nil
}

// decode rebuilds a stored copy from its on-disk form.
func (s *MessageStore) decode(pe persistedEnvelope) (*storedEnvelope, error) {
	var pb dmcnpb.EncryptedEnvelope
	if err := proto.Unmarshal(pe.Env, &pb); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	env, err := message.EncryptedEnvelopeFromProto(&pb)
	if err != nil {
		return nil, fmt.Errorf("invalid envelope: %w", err)
	}
	se := &storedEnvelope{Envelope: env, Addr: pe.Addr, StoredAt: s.now()}
	copy(se.Hash[:], pe.Hash)
	if pe.StoredAt != 0 {
		se.StoredAt = time.Unix(pe.StoredAt, 0)
	}
	return se, nil
}

// persist writes a stored envelope through to the datastore (no-op in-memory).
func (s *MessageStore) persist(se *storedEnvelope) error {
	if s.ds == nil {
		return nil
	}
	envBytes, err := proto.Marshal(se.Envelope.ToProto())
	if err != nil {
		return fmt.Errorf("marshal envelope %x: %w", se.Hash, err)
	}
	val, err := json.Marshal(persistedEnvelope{Addr: se.Addr, Hash: se.Hash[:], StoredAt: se.StoredAt.Unix(), Env: envBytes})
	if err != nil {
		return fmt.Errorf("marshal record %x: %w", se.Hash, err)
	}
	if err := s.ds.Put(context.Background(), relayStoreKey(se.Addr, se.Hash), val); err != nil {
		return fmt.Errorf("persist %x: %w", se.Hash, err)
	}
	return nil
}

// index adds a copy to the in-memory maps. Callers hold the write lock.
func (s *MessageStore) index(se *storedEnvelope) {
	s.byAddr[se.Addr] = append(s.byAddr[se.Addr], se)
	s.byHash[se.Hash] = append(s.byHash[se.Hash], se)
	s.count++
}

// find returns the copy of hash queued for addr, or nil. Callers hold a lock.
func (s *MessageStore) find(addr string, hash [32]byte) *storedEnvelope {
	for _, se := range s.byHash[hash] {
		if se.Addr == addr {
			return se
		}
	}
	return nil
}

// unindex takes one copy out of the in-memory maps, for the caller to delete from the datastore
// with deleteCopies once it has released the lock. Callers hold the write lock.
func (s *MessageStore) unindex(se *storedEnvelope) {
	isSe := func(e *storedEnvelope) bool { return e == se }
	if s.byAddr[se.Addr] = slices.DeleteFunc(s.byAddr[se.Addr], isSe); len(s.byAddr[se.Addr]) == 0 {
		delete(s.byAddr, se.Addr)
	}
	if s.byHash[se.Hash] = slices.DeleteFunc(s.byHash[se.Hash], isSe); len(s.byHash[se.Hash]) == 0 {
		delete(s.byHash, se.Hash)
	}
	s.count--
}

// deleteCopies deletes copies already taken out of the maps from the datastore, in one batch and
// without the store's lock, so a large delete never holds up STORE or FETCH. A copy stored again
// between the unindex and the delete — a retried STORE of the same envelope — would lose its
// fresh entry to that late delete, so afterwards any copy the maps hold again is written back.
func (s *MessageStore) deleteCopies(copies []*storedEnvelope) {
	if s.ds == nil || len(copies) == 0 {
		return
	}
	keys := make([]ds.Key, 0, 2*len(copies))
	for _, se := range copies {
		keys = append(keys, relayStoreKey(se.Addr, se.Hash), relayFetchedKey(se.Addr, se.Hash))
	}
	s.deleteKeys(keys)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, se := range copies {
		if again := s.find(se.Addr, se.Hash); again != nil {
			if err := s.persist(again); err != nil {
				s.log.Warnf("relay store: %v", err)
			}
		}
	}
}

// deleteKeys deletes entries from the datastore in one batch (no-op in-memory).
func (s *MessageStore) deleteKeys(keys []ds.Key) {
	if s.ds == nil || len(keys) == 0 {
		return
	}
	ctx := context.Background()
	b, err := s.ds.Batch(ctx)
	if err != nil {
		s.log.Warnf("relay store: delete %d entries: %v", len(keys), err)
		return
	}
	for _, k := range keys {
		if err := b.Delete(ctx, k); err != nil {
			s.log.Warnf("relay store: delete %s: %v", k, err)
		}
	}
	if err := b.Commit(ctx); err != nil {
		s.log.Warnf("relay store: delete %d entries: %v", len(keys), err)
	}
}

// Store queues an encrypted envelope for a recipient address. Storing the same envelope for the
// same recipient again is a no-op, so a retried STORE does not queue a second copy.
func (s *MessageStore) Store(recipientAddr string, env *message.EncryptedEnvelope, hash [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.find(recipientAddr, hash) != nil {
		return
	}
	se := &storedEnvelope{
		Envelope: env,
		Hash:     hash,
		Addr:     recipientAddr,
		StoredAt: s.now(),
	}
	s.index(se)
	if err := s.persist(se); err != nil {
		s.log.Warnf("relay store: %v", err)
	}
}

// Fetch returns every envelope queued for a recipient address along with its hash. It changes
// nothing: the FETCH handler calls MarkFetched once the envelopes are actually on their way.
func (s *MessageStore) Fetch(recipientAddr string) ([]*message.EncryptedEnvelope, [][32]byte) {
	queued := s.Queued(recipientAddr)
	envs := make([]*message.EncryptedEnvelope, len(queued))
	hashes := make([][32]byte, len(queued))
	for i, q := range queued {
		envs[i], hashes[i] = q.Envelope, q.Hash
	}
	return envs, hashes
}

// MarkFetched records that an authenticated FETCH by recipientAddr has handed these copies out,
// which is what lets an ACK delete them. Marked only once the response is written, so a FETCH
// that failed on the way leaves nothing another recipient's ACK could take.
func (s *MessageStore) MarkFetched(recipientAddr string, hashes [][32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range hashes {
		if se := s.find(recipientAddr, h); se != nil && !se.Fetched {
			se.Fetched = true
			if s.ds != nil {
				if err := s.ds.Put(context.Background(), relayFetchedKey(se.Addr, se.Hash), []byte{1}); err != nil {
					s.log.Warnf("relay store: mark %x fetched: %v", se.Hash, err)
				}
			}
		}
	}
}

// Queued lists every envelope queued for a recipient address with the time it was queued: for a
// consumer on this node, such as a co-located bridge, which deletes what it is finished with by
// Remove.
func (s *MessageStore) Queued(recipientAddr string) []QueuedEnvelope {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored := s.byAddr[recipientAddr]
	out := make([]QueuedEnvelope, len(stored))
	for i, se := range stored {
		out[i] = QueuedEnvelope{Envelope: se.Envelope, Hash: se.Hash, StoredAt: se.StoredAt}
	}
	return out
}

// Ack deletes a delivered envelope by its hash. The protocol's ACK names only the envelope, not
// who is acknowledging it, so it deletes the copies FETCH has handed out and no others: a copy
// another recipient has not collected yet, or one a co-located bridge reads locally, stays queued.
func (s *MessageStore) Ack(hash [32]byte) error {
	s.mu.Lock()
	var fetched []*storedEnvelope
	for _, se := range slices.Clone(s.byHash[hash]) {
		if se.Fetched {
			s.unindex(se)
			fetched = append(fetched, se)
		}
	}
	s.mu.Unlock()
	if len(fetched) == 0 {
		return ErrEnvelopeNotFound
	}
	s.deleteCopies(fetched)
	return nil
}

// Remove deletes one recipient's copy of an envelope, leaving any other recipient's copy queued.
func (s *MessageStore) Remove(recipientAddr string, hash [32]byte) error {
	s.mu.Lock()
	se := s.find(recipientAddr, hash)
	if se == nil {
		s.mu.Unlock()
		return ErrEnvelopeNotFound
	}
	s.unindex(se)
	s.mu.Unlock()
	s.deleteCopies([]*storedEnvelope{se})
	return nil
}

// Expire drops every envelope queued before the cutoff for its recipient address and reports
// how many it dropped. The lock covers only the in-memory maps; the datastore deletes follow in
// one batch after it is released.
func (s *MessageStore) Expire(cutoffFor func(addr string) time.Time) int {
	s.mu.Lock()
	var old []*storedEnvelope
	for addr, list := range s.byAddr {
		cutoff := cutoffFor(addr)
		for _, se := range list {
			if se.StoredAt.Before(cutoff) {
				old = append(old, se)
			}
		}
	}
	for _, se := range old {
		s.unindex(se)
	}
	s.mu.Unlock()
	s.deleteCopies(old)
	return len(old)
}

// Count returns the number of queued copies (one per envelope per recipient).
func (s *MessageStore) Count() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint32(s.count)
}
