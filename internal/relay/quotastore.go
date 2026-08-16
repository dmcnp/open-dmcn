package relay

import (
	"context"
	"fmt"
	"time"

	ds "github.com/ipfs/go-datastore"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// quotaPrefix namespaces the node's per-owner quota grants in the datastore, keyed by
// the owner's recipient X25519 hex (the same key the personal-KV store and the STORE
// free-ride guard use).
const quotaPrefix = "/quotas"

// QuotaStore is a node-local, self-encrypted map of recipient-X25519-hex → operator-signed
// RoleQuota Credential. It holds the per-account personal-storage allowances installed via
// the SetQuota op (minted on subscription payment). Credentials are sealed at rest with a
// node-held key — same treatment as AccountStore — so which owners hold an upgraded quota
// is not readable from disk. Each stored credential is DAR-chained (verified at install),
// so it can be re-verified after a mailbox handoff to a different relay.
type QuotaStore struct {
	store ds.Batching
	key   []byte // 32-byte AES key derived from a node-held secret
}

// NewQuotaStore derives a sealing key from the node secret and returns a store over the
// given (borrowed) datastore.
func NewQuotaStore(d ds.Batching, nodeSecret []byte) (*QuotaStore, error) {
	key, err := crypto.DeriveKey(nodeSecret, []byte("dmcn-quota-store-v1"), nil, 32)
	if err != nil {
		return nil, fmt.Errorf("quotas: derive key: %w", err)
	}
	return &QuotaStore{store: d, key: key}, nil
}

func quotaKey(rxHex string) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s", quotaPrefix, rxHex))
}

// seal/open store the grant bytes as nonce(12) || tag(16) || ciphertext.
func (q *QuotaStore) seal(grant []byte) ([]byte, error) {
	nonce, ct, tag, err := crypto.AESGCMEncrypt(q.key, grant)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(tag)+len(ct))
	out = append(out, nonce...)
	out = append(out, tag...)
	out = append(out, ct...)
	return out, nil
}

func (q *QuotaStore) open(blob []byte) ([]byte, error) {
	if len(blob) < 12+16 {
		return nil, fmt.Errorf("quotas: sealed entry too short")
	}
	nonce, tag, ct := blob[:12], blob[12:28], blob[28:]
	return crypto.AESGCMDecrypt(q.key, nonce, ct, tag)
}

// Put records the marshaled quota credential for an owner (idempotent — a re-put
// overwrites, which is how a renewal or downgrade lands).
func (q *QuotaStore) Put(ctx context.Context, rxHex string, cred []byte) error {
	if rxHex == "" {
		return fmt.Errorf("quotas: empty rxHex")
	}
	blob, err := q.seal(cred)
	if err != nil {
		return err
	}
	if err := q.store.Put(ctx, quotaKey(rxHex), blob); err != nil {
		return fmt.Errorf("quotas: put: %w", err)
	}
	return nil
}

// Get returns the stored quota credential for an owner (parsed), or ok=false when none is
// on file. It does NOT re-check the DAR chain (verified at install) or the time window —
// use EffectiveQuota for enforcement.
func (q *QuotaStore) Get(ctx context.Context, rxHex string) (cred *identity.Credential, ok bool, err error) {
	raw, ok, err := q.Raw(ctx, rxHex)
	if err != nil || !ok {
		return nil, ok, err
	}
	c, err := identity.CredentialFromProtoBytes(raw)
	if err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// Raw returns the stored (unsealed) marshaled credential bytes for an owner, for
// re-pushing during a mailbox handoff. ok=false when none is on file.
func (q *QuotaStore) Raw(ctx context.Context, rxHex string) (cred []byte, ok bool, err error) {
	blob, err := q.store.Get(ctx, quotaKey(rxHex))
	if err == ds.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("quotas: get: %w", err)
	}
	raw, err := q.open(blob)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// EffectiveQuota returns the quota bytes from a currently-valid credential for an owner, or
// ok=false when there is none or it is outside its validity window (so the caller falls
// back to the node default). The DAR chain was verified at install (SetQuota); here we only
// re-check the credential's NotAfter window.
func (q *QuotaStore) EffectiveQuota(ctx context.Context, rxHex string, now time.Time) (quota uint64, ok bool) {
	c, present, err := q.Get(ctx, rxHex)
	if err != nil || !present {
		return 0, false
	}
	if !c.NotAfter.IsZero() && now.After(c.NotAfter) {
		return 0, false // lapsed — revert to the node default
	}
	return identity.QuotaBytesOf(c), true
}

// Remove drops an owner's quota credential (idempotent) — e.g. a subscription cancellation
// that reverts to the node default.
func (q *QuotaStore) Remove(ctx context.Context, rxHex string) error {
	if err := q.store.Delete(ctx, quotaKey(rxHex)); err != nil {
		return fmt.Errorf("quotas: remove: %w", err)
	}
	return nil
}
