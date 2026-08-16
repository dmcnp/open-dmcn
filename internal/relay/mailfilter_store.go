package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	ds "github.com/ipfs/go-datastore"

	"dmcn.dev/open-dmcn/internal/core/message"
)

// mailFilterPrefix namespaces recipient filter blobs in the datastore, keyed by
// the recipient's X25519 public key (hex) — the same key mailboxes use.
const mailFilterPrefix = "/dmcn/mailfilter"

// PersistentMailFilterStore stores each recipient's sealed (dual-wrapped) mail
// filter blob in the node's datastore. It satisfies MailFilterStore (read side)
// and adds Put/Delete for the owner-facing API. The server only ever holds
// ciphertext; it can decrypt at STORE only because the blob is also sealed to the
// relay's mailbox key.
type PersistentMailFilterStore struct {
	store ds.Batching
}

// NewMailFilterStore returns a filter store over the given (borrowed) datastore.
func NewMailFilterStore(d ds.Batching) *PersistentMailFilterStore {
	return &PersistentMailFilterStore{store: d}
}

func mailFilterKey(rxHex string) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s", mailFilterPrefix, rxHex))
}

// GetFilter returns the recipient's sealed filter blob, or (nil, nil) if none.
func (s *PersistentMailFilterStore) GetFilter(ctx context.Context, recipientHex string) (*message.SealedBlob, error) {
	data, err := s.store.Get(ctx, mailFilterKey(recipientHex))
	if errors.Is(err, ds.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var blob message.SealedBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, fmt.Errorf("relay: mail filter unmarshal: %w", err)
	}
	return &blob, nil
}

// PutFilter stores (overwrites) the recipient's sealed filter blob. The caller is
// responsible for authenticating the owner before calling.
func (s *PersistentMailFilterStore) PutFilter(ctx context.Context, recipientHex string, blob *message.SealedBlob) error {
	data, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("relay: mail filter marshal: %w", err)
	}
	return s.store.Put(ctx, mailFilterKey(recipientHex), data)
}

// DeleteFilter removes a recipient's filter (reverts to allow-everything).
func (s *PersistentMailFilterStore) DeleteFilter(ctx context.Context, recipientHex string) error {
	return s.store.Delete(ctx, mailFilterKey(recipientHex))
}
