package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// Mailbox key layout, all under /mbox. recipientHex is the 64-char hex of the
// recipient's X25519 public key (fixed width, so no recipient key is a prefix of
// another):
//
//	/mbox/h/<rxHex>/<seq>/<hashHex>  -> MailboxEntry (small, listable header view)
//	/mbox/b/<rxHex>/<hashHex>        -> MailboxBody  (large, fetched on open)
//	/mbox/x/<rxHex>/<hashHex>        -> the header key (hash index, for Delete)
//
// seq is the zero-padded store time in nanoseconds, so a key range-scan over the
// header prefix yields messages in chronological (oldest-first) order — which is
// also a stable pagination order.
const (
	mboxHeaderPrefix = "/mbox/h"
	mboxBodyPrefix   = "/mbox/b"
	mboxIndexPrefix  = "/mbox/x"

	// defaultListLimit caps an unbounded FETCH-LIST page.
	defaultListLimit = 50
)

// MailboxStore is a durable, hold-until-deleted mailbox backed by an ordered
// (leveldb) datastore. Messages are stored split — a small header entry and a
// separate body entry — so listing an inbox never reads message bodies. Nothing
// expires and nothing is consumed on read: only an explicit Delete removes a
// message. This is the recipient's authoritative, re-syncable home for mail.
type MailboxStore struct {
	store ds.Batching
}

// NewMailboxStore returns a MailboxStore over the given (borrowed) datastore.
// The datastore must iterate keys in sorted order (leveldb does); pagination
// relies on it.
func NewMailboxStore(d ds.Batching) *MailboxStore {
	return &MailboxStore{store: d}
}

func headerPrefix(rxHex string) string {
	return fmt.Sprintf("%s/%s", mboxHeaderPrefix, rxHex)
}

func headerKey(rxHex, seq, hashHex string) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s/%s/%s", mboxHeaderPrefix, rxHex, seq, hashHex))
}

func bodyKey(rxHex, hashHex string) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s/%s", mboxBodyPrefix, rxHex, hashHex))
}

func indexKey(rxHex, hashHex string) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s/%s", mboxIndexPrefix, rxHex, hashHex))
}

// mailboxEntrySize is the per-recipient byte size a stored envelope contributes to a
// mailbox, matching StatsOwner/Stats accounting (BodySize + encrypted-header length).
// Used by the STORE quota gate to predict the post-store usage before writing.
func mailboxEntrySize(env *message.EncryptedEnvelope) uint64 {
	return uint64(len(env.EncryptedBody)) + uint64(len(env.EncryptedHeader))
}

func recipientsToProto(recs []message.RecipientRecord) []*dmcnpb.RecipientRecord {
	out := make([]*dmcnpb.RecipientRecord, len(recs))
	for i := range recs {
		r := recs[i]
		out[i] = &dmcnpb.RecipientRecord{
			DeviceId:      r.DeviceID[:],
			RecipientXPub: r.RecipientXPub[:],
			EphemeralXPub: r.EphemeralXPub[:],
			WrappedCek:    r.WrappedCEK,
			CekNonce:      r.CEKNonce[:],
			CekTag:        r.CEKTag[:],
			// Kdf MUST be carried. It names the derivation the wrap used, so dropping it here
			// makes every stored message unreadable AND changes the envelope's canonical bytes,
			// breaking the STORE signature the relay recomputes. This hand-written conversion is
			// exactly where protocol fields go missing — add new ones here too.
			Kdf: r.KDF,
		}
	}
	return out
}

// Store persists a split envelope into the recipient's mailbox. It is idempotent
// by hash: re-storing the same message (e.g. a retried STORE) is a no-op. The
// envelope must be in split header/body form.
func (m *MailboxStore) Store(ctx context.Context, rxHex string, hash [32]byte, env *message.EncryptedEnvelope, storedAt time.Time) error {
	if !env.IsSplit() {
		return errors.New("mailbox: store requires a split (header/body) envelope")
	}

	hashHex := hex.EncodeToString(hash[:])
	idxK := indexKey(rxHex, hashHex)

	if has, err := m.store.Has(ctx, idxK); err != nil {
		return fmt.Errorf("mailbox: store: index check: %w", err)
	} else if has {
		return nil // already stored
	}

	seq := fmt.Sprintf("%020d", storedAt.UnixNano())
	hKey := headerKey(rxHex, seq, hashHex)

	entry := &dmcnpb.MailboxEntry{
		Hash:               hash[:],
		StoredAt:           storedAt.Unix(),
		BodySize:           uint64(len(env.EncryptedBody)),
		Recipients:         recipientsToProto(env.Recipients),
		EncryptedHeader:    env.EncryptedHeader,
		HeaderNonce:        env.HeaderNonce[:],
		HeaderTag:          env.HeaderTag[:],
		HeaderSizeClass:    env.HeaderSizeClass,
		BodyContentAddress: env.BodyContentAddress, // durable pointer future dedup keys on
	}
	body := &dmcnpb.MailboxBody{
		EncryptedBody:      env.EncryptedBody,
		BodyNonce:          env.BodyNonce[:],
		BodyTag:            env.BodyTag[:],
		BodySizeClass:      env.BodySizeClass,
		BodyContentAddress: env.BodyContentAddress,
	}

	entryBytes, err := proto.Marshal(entry)
	if err != nil {
		return fmt.Errorf("mailbox: store: marshal entry: %w", err)
	}
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		return fmt.Errorf("mailbox: store: marshal body: %w", err)
	}

	batch, err := m.store.Batch(ctx)
	if err != nil {
		return fmt.Errorf("mailbox: store: batch: %w", err)
	}
	if err := batch.Put(ctx, hKey, entryBytes); err != nil {
		return fmt.Errorf("mailbox: store: put header: %w", err)
	}
	if err := batch.Put(ctx, bodyKey(rxHex, hashHex), bodyBytes); err != nil {
		return fmt.Errorf("mailbox: store: put body: %w", err)
	}
	if err := batch.Put(ctx, idxK, []byte(hKey.String())); err != nil {
		return fmt.Errorf("mailbox: store: put index: %w", err)
	}
	if err := batch.Commit(ctx); err != nil {
		return fmt.Errorf("mailbox: store: commit: %w", err)
	}
	return nil
}

// List returns up to limit header entries for the recipient in chronological
// (oldest-first) order, starting strictly after cursor (empty cursor = from the
// beginning). nextCursor is the cursor for the following page, or empty when the
// mailbox has been fully drained. Listing is non-consuming.
func (m *MailboxStore) List(ctx context.Context, rxHex string, limit int, cursor string) (entries []*dmcnpb.MailboxEntry, nextCursor string, err error) {
	if limit <= 0 {
		limit = defaultListLimit
	}

	res, err := m.store.Query(ctx, dsquery.Query{Prefix: headerPrefix(rxHex)})
	if err != nil {
		return nil, "", fmt.Errorf("mailbox: list: query: %w", err)
	}
	defer res.Close()

	lastKey := ""
	for r := range res.Next() {
		if r.Error != nil {
			return nil, "", fmt.Errorf("mailbox: list: %w", r.Error)
		}
		// Skip everything at or before the cursor (keys iterate sorted ascending).
		if cursor != "" && r.Key <= cursor {
			continue
		}
		e := &dmcnpb.MailboxEntry{}
		if err := proto.Unmarshal(r.Value, e); err != nil {
			continue // skip a corrupt entry rather than failing the whole page
		}
		entries = append(entries, e)
		lastKey = r.Key
		if len(entries) >= limit {
			break
		}
	}

	// A full page means there may be more; hand back a cursor to continue. The
	// final (partial or empty) page returns an empty cursor.
	if len(entries) == limit {
		nextCursor = lastKey
	}
	return entries, nextCursor, nil
}

// GetBody returns the stored body for a message, or ErrEnvelopeNotFound.
func (m *MailboxStore) GetBody(ctx context.Context, rxHex string, hash [32]byte) (*dmcnpb.MailboxBody, error) {
	v, err := m.store.Get(ctx, bodyKey(rxHex, hex.EncodeToString(hash[:])))
	if errors.Is(err, ds.ErrNotFound) {
		return nil, ErrEnvelopeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mailbox: get body: %w", err)
	}
	body := &dmcnpb.MailboxBody{}
	if err := proto.Unmarshal(v, body); err != nil {
		return nil, fmt.Errorf("mailbox: get body: unmarshal: %w", err)
	}
	return body, nil
}

// Delete removes a message (header + body + index) from the recipient's mailbox.
// It is idempotent: deleting a message that is not present is not an error. This
// is the only way mail leaves a mailbox — there is no expiry.
func (m *MailboxStore) Delete(ctx context.Context, rxHex string, hash [32]byte) error {
	hashHex := hex.EncodeToString(hash[:])
	idxK := indexKey(rxHex, hashHex)

	hKeyBytes, err := m.store.Get(ctx, idxK)
	if errors.Is(err, ds.ErrNotFound) {
		return nil // nothing to delete
	}
	if err != nil {
		return fmt.Errorf("mailbox: delete: index: %w", err)
	}

	batch, err := m.store.Batch(ctx)
	if err != nil {
		return fmt.Errorf("mailbox: delete: batch: %w", err)
	}
	if err := batch.Delete(ctx, ds.NewKey(string(hKeyBytes))); err != nil {
		return fmt.Errorf("mailbox: delete: header: %w", err)
	}
	if err := batch.Delete(ctx, bodyKey(rxHex, hashHex)); err != nil {
		return fmt.Errorf("mailbox: delete: body: %w", err)
	}
	if err := batch.Delete(ctx, idxK); err != nil {
		return fmt.Errorf("mailbox: delete: index: %w", err)
	}
	if err := batch.Commit(ctx); err != nil {
		return fmt.Errorf("mailbox: delete: commit: %w", err)
	}
	return nil
}

// Stats reports the total number of stored messages and their approximate byte size
// across all mailboxes, for load-aware placement. It scans only the small header entries
// (which carry BodySize) — never the bodies — so it is cheap relative to total stored data.
func (m *MailboxStore) Stats(ctx context.Context) (messages, bytes uint64, err error) {
	return m.statsPrefix(ctx, mboxHeaderPrefix)
}

// StatsOwner reports the stored message count + approximate byte size held for one
// recipient (keyed by X25519 hex), for per-account quota accounting. Like Stats it
// scans only the recipient's small header entries (BodySize + header length) — never
// the bodies. The byte figure matches what Stats folds into total occupancy, so the
// per-owner and global numbers use one accounting.
func (m *MailboxStore) StatsOwner(ctx context.Context, rxHex string) (messages, bytes uint64, err error) {
	return m.statsPrefix(ctx, headerPrefix(rxHex))
}

func (m *MailboxStore) statsPrefix(ctx context.Context, prefix string) (messages, bytes uint64, err error) {
	res, err := m.store.Query(ctx, dsquery.Query{Prefix: prefix})
	if err != nil {
		return 0, 0, fmt.Errorf("mailbox: stats: query: %w", err)
	}
	defer res.Close()
	for r := range res.Next() {
		if r.Error != nil {
			return 0, 0, fmt.Errorf("mailbox: stats: %w", r.Error)
		}
		e := &dmcnpb.MailboxEntry{}
		if err := proto.Unmarshal(r.Value, e); err != nil {
			continue // skip a corrupt entry
		}
		messages++
		bytes += e.BodySize + uint64(len(e.EncryptedHeader))
	}
	return messages, bytes, nil
}

// EnvelopeFromEntry reconstructs a header-only EncryptedEnvelope from a mailbox
// list entry — enough to decrypt and verify the header (preview) without the body.
func EnvelopeFromEntry(entry *dmcnpb.MailboxEntry) (*message.EncryptedEnvelope, error) {
	return message.EncryptedEnvelopeFromProto(&dmcnpb.EncryptedEnvelope{
		Recipients:      entry.Recipients,
		EncryptedHeader: entry.EncryptedHeader,
		HeaderNonce:     entry.HeaderNonce,
		HeaderTag:       entry.HeaderTag,
		HeaderSizeClass: entry.HeaderSizeClass,
	})
}

// EnvelopeFromParts reconstructs a full split EncryptedEnvelope from a mailbox
// list entry and its fetched body, for decrypting and verifying the body.
func EnvelopeFromParts(entry *dmcnpb.MailboxEntry, body *dmcnpb.MailboxBody) (*message.EncryptedEnvelope, error) {
	return message.EncryptedEnvelopeFromProto(&dmcnpb.EncryptedEnvelope{
		Recipients:         entry.Recipients,
		EncryptedHeader:    entry.EncryptedHeader,
		HeaderNonce:        entry.HeaderNonce,
		HeaderTag:          entry.HeaderTag,
		HeaderSizeClass:    entry.HeaderSizeClass,
		EncryptedBody:      body.EncryptedBody,
		BodyNonce:          body.BodyNonce,
		BodyTag:            body.BodyTag,
		BodySizeClass:      body.BodySizeClass,
		BodyContentAddress: entry.BodyContentAddress,
	})
}

// Count returns the number of messages held for a recipient.
func (m *MailboxStore) Count(ctx context.Context, rxHex string) (int, error) {
	res, err := m.store.Query(ctx, dsquery.Query{Prefix: headerPrefix(rxHex), KeysOnly: true})
	if err != nil {
		return 0, fmt.Errorf("mailbox: count: %w", err)
	}
	defer res.Close()

	n := 0
	for r := range res.Next() {
		if r.Error != nil {
			return 0, fmt.Errorf("mailbox: count: %w", r.Error)
		}
		n++
	}
	return n, nil
}
