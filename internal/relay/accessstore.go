package relay

import (
	"context"
	"fmt"
	"time"

	ds "github.com/ipfs/go-datastore"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// accessPrefix namespaces the node's per-account ACCESS assertions in the datastore, keyed by
// the owner's recipient X25519 hex (the same key the quota/personal-KV stores use), then the
// assertion's mode. Up to two assertions are held per account:
//
//	/access/<rxHex>/open        -> operator-signed RoleAccess "open" assertion
//	/access/<rxHex>/suspended   -> operator-signed RoleAccess "suspended" assertion
//
// The account's live mode (open/suspended/closed) is DERIVED from which assertion's
// [EffectiveFrom, NotAfter] window contains now (identity.DeriveAccessMode); absence of both
// ⇒ open (default-open). "closed" is never stored — it is the terminal when assertions exist
// but none is currently in effect.
const accessPrefix = "/access"

// AccessStore is a node-local, self-encrypted map of (recipient-X25519-hex, mode) → operator-
// signed RoleAccess Credential. Like QuotaStore it seals each stored credential at rest with a
// node-held key, so which accounts are managed/suspended is not readable from disk. Each stored
// credential is self-authenticating (verified at install), so it re-verifies after a handoff.
type AccessStore struct {
	store ds.Batching
	key   []byte // 32-byte AES key derived from a node-held secret
}

// NewAccessStore derives a sealing key from the node secret and returns a store over the given
// (borrowed) datastore.
func NewAccessStore(d ds.Batching, nodeSecret []byte) (*AccessStore, error) {
	key, err := crypto.DeriveKey(nodeSecret, []byte("dmcn-access-store-v1"), nil, 32)
	if err != nil {
		return nil, fmt.Errorf("access: derive key: %w", err)
	}
	return &AccessStore{store: d, key: key}, nil
}

// validAccessMode reports whether mode is an assertion mode the store persists.
func validAccessMode(mode string) bool {
	return mode == identity.AccessOpen || mode == identity.AccessSuspended
}

func accessKey(rxHex, mode string) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s/%s", accessPrefix, rxHex, mode))
}

// seal/open store the grant bytes as nonce(12) || tag(16) || ciphertext (same layout as QuotaStore).
func (a *AccessStore) seal(grant []byte) ([]byte, error) {
	nonce, ct, tag, err := crypto.AESGCMEncrypt(a.key, grant)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(tag)+len(ct))
	out = append(out, nonce...)
	out = append(out, tag...)
	out = append(out, ct...)
	return out, nil
}

func (a *AccessStore) open(blob []byte) ([]byte, error) {
	if len(blob) < 12+16 {
		return nil, fmt.Errorf("access: sealed entry too short")
	}
	nonce, tag, ct := blob[:12], blob[12:28], blob[28:]
	return crypto.AESGCMDecrypt(a.key, nonce, ct, tag)
}

// Put records the marshaled access assertion for an owner under the given mode (idempotent —
// a re-put overwrites, which is how a renewal lands).
func (a *AccessStore) Put(ctx context.Context, rxHex, mode string, cred []byte) error {
	if rxHex == "" {
		return fmt.Errorf("access: empty rxHex")
	}
	if !validAccessMode(mode) {
		return fmt.Errorf("access: invalid mode %q", mode)
	}
	blob, err := a.seal(cred)
	if err != nil {
		return err
	}
	if err := a.store.Put(ctx, accessKey(rxHex, mode), blob); err != nil {
		return fmt.Errorf("access: put: %w", err)
	}
	return nil
}

// Raw returns the stored (unsealed) marshaled credential bytes for an owner+mode, for
// re-pushing during a mailbox handoff. ok=false when none is on file.
func (a *AccessStore) Raw(ctx context.Context, rxHex, mode string) (cred []byte, ok bool, err error) {
	blob, err := a.store.Get(ctx, accessKey(rxHex, mode))
	if err == ds.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("access: get: %w", err)
	}
	raw, err := a.open(blob)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// Get returns the parsed access assertion for an owner+mode, or ok=false when none is on file.
// It does NOT re-check the credential window — use EffectiveAccess for the derived mode.
func (a *AccessStore) Get(ctx context.Context, rxHex, mode string) (cred *identity.Credential, ok bool, err error) {
	raw, ok, err := a.Raw(ctx, rxHex, mode)
	if err != nil || !ok {
		return nil, ok, err
	}
	c, err := identity.CredentialFromProtoBytes(raw)
	if err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// Remove drops one of an owner's access assertions (idempotent) — e.g. an admin clearing the
// open assertion to force immediate suspension, or clearing both to make the account unmanaged.
func (a *AccessStore) Remove(ctx context.Context, rxHex, mode string) error {
	if err := a.store.Delete(ctx, accessKey(rxHex, mode)); err != nil {
		return fmt.Errorf("access: remove: %w", err)
	}
	return nil
}

// EffectiveAccess returns the account's live access mode (open/suspended/closed) derived from
// its installed assertions as of now. managed=false means neither assertion is on file, so the
// caller treats the account as open (default-open). A store error surfaces (fail closed at the
// caller's discretion).
func (a *AccessStore) EffectiveAccess(ctx context.Context, rxHex string, now time.Time) (mode string, managed bool, err error) {
	openCred, openOK, err := a.Get(ctx, rxHex, identity.AccessOpen)
	if err != nil {
		return "", false, err
	}
	suspCred, suspOK, err := a.Get(ctx, rxHex, identity.AccessSuspended)
	if err != nil {
		return "", false, err
	}
	if !openOK && !suspOK {
		return identity.AccessOpen, false, nil
	}
	return identity.DeriveAccessMode(openCred, suspCred, now), true, nil
}
