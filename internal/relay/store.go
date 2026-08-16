// Package relay implements the DMCN relay node protocol for message
// storage and delivery. See whitepaper Section 15.4.2 and PRD Section 5.2.
package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"
	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/dmcnpb"
)

// relayStorePrefix namespaces durable relay-store keys in a (possibly shared)
// datastore. Each in-flight envelope is one key: /dmcn/relaystore/<hashHex>.
const relayStorePrefix = "/dmcn/relaystore"

func relayStoreKey(hash [32]byte) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s", relayStorePrefix, hex.EncodeToString(hash[:])))
}

// persistedEnvelope is the on-disk form of a storedEnvelope. The envelope itself
// is stored as deterministic protobuf; the JSON wrapper carries the routing
// address and delivery status that the in-memory index needs to rebuild on open.
type persistedEnvelope struct {
	Addr   string `json:"addr"`
	Hash   []byte `json:"hash"`
	Status int    `json:"status"`
	Env    []byte `json:"env"`
}

// DeliveryStatus represents the state of a stored envelope.
type DeliveryStatus int

const (
	// Pending means the envelope has not been fetched yet.
	Pending DeliveryStatus = iota
	// Delivered means the recipient has acknowledged receipt.
	Delivered
)

var (
	// ErrEnvelopeNotFound is returned when an envelope hash is not in the store.
	ErrEnvelopeNotFound = errors.New("relay: envelope not found")
)

// storedEnvelope holds an envelope along with its delivery metadata.
type storedEnvelope struct {
	Envelope *message.EncryptedEnvelope
	Hash     [32]byte
	Addr     string
	Status   DeliveryStatus
}

// MessageStore holds in-flight encrypted envelopes for relay STORE/FETCH/ACK,
// indexed by recipient address. The in-memory maps are the fast read path; when
// a datastore is configured (NewPersistentMessageStore) every mutation is also
// written through to disk and the maps are rebuilt on open, so queued mail
// survives a restart.
type MessageStore struct {
	mu     sync.RWMutex
	byAddr map[string][]*storedEnvelope // recipient address → envelopes
	byHash map[[32]byte]*storedEnvelope // envelope hash → envelope

	ds  ds.Batching // nil ⇒ in-memory only
	log logr.Logger // used only on the persistent path
}

// NewMessageStore creates an empty in-memory message store (no persistence).
func NewMessageStore() *MessageStore {
	return &MessageStore{
		byAddr: make(map[string][]*storedEnvelope),
		byHash: make(map[[32]byte]*storedEnvelope),
	}
}

// NewPersistentMessageStore creates a message store backed by a datastore. Any
// envelopes already on disk are loaded into the in-memory index, so in-flight
// mail survives a process restart.
func NewPersistentMessageStore(d ds.Batching, log logr.Logger) (*MessageStore, error) {
	s := &MessageStore{
		byAddr: make(map[string][]*storedEnvelope),
		byHash: make(map[[32]byte]*storedEnvelope),
		ds:     d,
		log:    log,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load rebuilds the in-memory index from the datastore. A corrupt entry is
// skipped (logged) rather than failing the whole load.
func (s *MessageStore) load() error {
	res, err := s.ds.Query(context.Background(), dsquery.Query{Prefix: relayStorePrefix})
	if err != nil {
		return fmt.Errorf("relay store: load query: %w", err)
	}
	defer res.Close()

	n := 0
	for r := range res.Next() {
		if r.Error != nil {
			return fmt.Errorf("relay store: load: %w", r.Error)
		}
		var pe persistedEnvelope
		if err := json.Unmarshal(r.Value, &pe); err != nil {
			s.log.Warnf("relay store: skip corrupt entry %s: %v", r.Key, err)
			continue
		}
		var pb dmcnpb.EncryptedEnvelope
		if err := proto.Unmarshal(pe.Env, &pb); err != nil {
			s.log.Warnf("relay store: skip unmarshalable envelope %s: %v", r.Key, err)
			continue
		}
		env, err := message.EncryptedEnvelopeFromProto(&pb)
		if err != nil {
			s.log.Warnf("relay store: skip invalid envelope %s: %v", r.Key, err)
			continue
		}
		se := &storedEnvelope{Envelope: env, Addr: pe.Addr, Status: DeliveryStatus(pe.Status)}
		copy(se.Hash[:], pe.Hash)
		s.byAddr[pe.Addr] = append(s.byAddr[pe.Addr], se)
		s.byHash[se.Hash] = se
		n++
	}
	if n > 0 {
		s.log.Infof("relay store: recovered %d in-flight envelope(s) from disk", n)
	}
	return nil
}

// persist writes a stored envelope through to the datastore (no-op in-memory).
// Keyed by hash, so it is idempotent and a status change overwrites in place.
func (s *MessageStore) persist(se *storedEnvelope) {
	if s.ds == nil {
		return
	}
	envBytes, err := proto.Marshal(se.Envelope.ToProto())
	if err != nil {
		s.log.Warnf("relay store: marshal envelope %x: %v", se.Hash, err)
		return
	}
	val, err := json.Marshal(persistedEnvelope{Addr: se.Addr, Hash: se.Hash[:], Status: int(se.Status), Env: envBytes})
	if err != nil {
		s.log.Warnf("relay store: marshal record %x: %v", se.Hash, err)
		return
	}
	if err := s.ds.Put(context.Background(), relayStoreKey(se.Hash), val); err != nil {
		s.log.Warnf("relay store: persist %x: %v", se.Hash, err)
	}
}

// Store adds an encrypted envelope to the store, indexed by recipient address.
func (s *MessageStore) Store(recipientAddr string, env *message.EncryptedEnvelope, hash [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	se := &storedEnvelope{
		Envelope: env,
		Hash:     hash,
		Addr:     recipientAddr,
		Status:   Pending,
	}

	s.byAddr[recipientAddr] = append(s.byAddr[recipientAddr], se)
	s.byHash[hash] = se
	s.persist(se)
}

// Fetch returns all pending envelopes for a recipient address along with
// their hashes. Does not remove them from the store.
func (s *MessageStore) Fetch(recipientAddr string) ([]*message.EncryptedEnvelope, [][32]byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored := s.byAddr[recipientAddr]
	var envs []*message.EncryptedEnvelope
	var hashes [][32]byte
	for _, se := range stored {
		if se.Status == Pending {
			envs = append(envs, se.Envelope)
			hashes = append(hashes, se.Hash)
		}
	}
	return envs, hashes
}

// Ack marks an envelope as delivered by its hash.
func (s *MessageStore) Ack(hash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	se, ok := s.byHash[hash]
	if !ok {
		return ErrEnvelopeNotFound
	}
	se.Status = Delivered
	s.persist(se)
	return nil
}

// DeliveryStatusOf returns the delivery status of an envelope by its hash.
func (s *MessageStore) DeliveryStatusOf(hash [32]byte) (DeliveryStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	se, ok := s.byHash[hash]
	if !ok {
		return 0, ErrEnvelopeNotFound
	}
	return se.Status, nil
}

// Count returns the total number of stored envelopes.
func (s *MessageStore) Count() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint32(len(s.byHash))
}
