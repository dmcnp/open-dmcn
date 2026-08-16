package relay

import (
	"context"
	"encoding/hex"
	"fmt"

	ds "github.com/ipfs/go-datastore"
	dsquery "github.com/ipfs/go-datastore/query"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// accountPrefix namespaces the node's account list in the datastore.
const accountPrefix = "/accounts"

// accountHexPrefix namespaces the node's rxHex index — the recipient X25519 pubkeys (hex) of
// the mailboxes it was assigned. It lets the STORE path reject mail for recipients this node
// was never assigned (the anti-free-ride guard) WITHOUT a global rxHex→address index: this is
// node-local, and the mailbox store already keys ciphertext by rxHex, so it adds no new
// at-rest leakage. A presence marker only (no address stored under the hex key).
const accountHexPrefix = "/accounts-hex"

// AccountStore is a node-local, self-encrypted set of the addresses a relay hosts a
// mailbox for. It is the (deliberately) node-private reverse of the rxHex→address gap:
// rather than publish a globally-readable index (which would deanonymize recipients), the
// node records its own assigned addresses, sealed at rest with a node-held key, and
// releases them only to an authority/sub-authority caller (the drain flow). Entries are
// added only from authorized assignments (RequestMailbox) or authenticated FETCHes, so the
// list cannot be poisoned.
type AccountStore struct {
	store ds.Batching
	key   []byte // 32-byte AES key derived from a node-held secret
}

// NewAccountStore derives a sealing key from the node secret and returns a store over the
// given (borrowed) datastore.
func NewAccountStore(d ds.Batching, nodeSecret []byte) (*AccountStore, error) {
	key, err := crypto.DeriveKey(nodeSecret, []byte("dmcn-account-store-v1"), nil, 32)
	if err != nil {
		return nil, fmt.Errorf("accounts: derive key: %w", err)
	}
	return &AccountStore{store: d, key: key}, nil
}

func accountKey(address string) ds.Key {
	h := crypto.SHA256Hash([]byte(address))
	return ds.NewKey(fmt.Sprintf("%s/%s", accountPrefix, hex.EncodeToString(h[:])))
}

func accountHexKey(rxHex string) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s", accountHexPrefix, rxHex))
}

// seal/open store the address as nonce(12) || tag(16) || ciphertext.
func (a *AccountStore) seal(address string) ([]byte, error) {
	nonce, ct, tag, err := crypto.AESGCMEncrypt(a.key, []byte(address))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(tag)+len(ct))
	out = append(out, nonce...)
	out = append(out, tag...)
	out = append(out, ct...)
	return out, nil
}

func (a *AccountStore) open(blob []byte) (string, error) {
	if len(blob) < 12+16 {
		return "", fmt.Errorf("accounts: sealed entry too short")
	}
	nonce, tag, ct := blob[:12], blob[12:28], blob[28:]
	pt, err := crypto.AESGCMDecrypt(a.key, nonce, ct, tag)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Record adds an address to the set (idempotent — a re-record just overwrites).
func (a *AccountStore) Record(ctx context.Context, address string) error {
	blob, err := a.seal(address)
	if err != nil {
		return err
	}
	if err := a.store.Put(ctx, accountKey(address), blob); err != nil {
		return fmt.Errorf("accounts: record: %w", err)
	}
	return nil
}

// Has reports whether the address is in the set.
func (a *AccountStore) Has(ctx context.Context, address string) (bool, error) {
	return a.store.Has(ctx, accountKey(address))
}

// RecordHex marks a recipient X25519 pubkey (hex) as an assigned mailbox on this node, so the
// STORE path can recognize mail for recipients it was actually assigned (idempotent).
func (a *AccountStore) RecordHex(ctx context.Context, rxHex string) error {
	if rxHex == "" {
		return nil
	}
	if err := a.store.Put(ctx, accountHexKey(rxHex), []byte{1}); err != nil {
		return fmt.Errorf("accounts: record hex: %w", err)
	}
	return nil
}

// HasHex reports whether rxHex is an assigned mailbox on this node.
func (a *AccountStore) HasHex(ctx context.Context, rxHex string) (bool, error) {
	return a.store.Has(ctx, accountHexKey(rxHex))
}

// Remove drops an address from the set (idempotent).
func (a *AccountStore) Remove(ctx context.Context, address string) error {
	if err := a.store.Delete(ctx, accountKey(address)); err != nil {
		return fmt.Errorf("accounts: remove: %w", err)
	}
	return nil
}

// Accounts returns every hosted address (decrypted).
func (a *AccountStore) Accounts(ctx context.Context) ([]string, error) {
	res, err := a.store.Query(ctx, dsquery.Query{Prefix: accountPrefix})
	if err != nil {
		return nil, fmt.Errorf("accounts: list: %w", err)
	}
	defer res.Close()
	var out []string
	for r := range res.Next() {
		if r.Error != nil {
			return nil, fmt.Errorf("accounts: list: %w", r.Error)
		}
		addr, err := a.open(r.Value)
		if err != nil {
			continue // skip a corrupt entry rather than failing the whole export
		}
		out = append(out, addr)
	}
	return out, nil
}
