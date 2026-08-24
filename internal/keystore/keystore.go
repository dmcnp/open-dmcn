// Package keystore provides encrypted on-disk storage for identity key material.
// The keystore file is encrypted with AES-256-GCM using a key derived from
// a user-supplied passphrase via HKDF-SHA256.
package keystore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

var (
	// ErrNotFound is returned when an address is not in the keystore.
	ErrNotFound = errors.New("keystore: identity not found")
	// ErrDecryptionFailed is returned when the passphrase is wrong.
	ErrDecryptionFailed = errors.New("keystore: decryption failed (wrong passphrase?)")
)

// hkdfInfo is the domain separation string for keystore key derivation.
var hkdfInfo = []byte("dmcn-keystore-v1")

// Keystore manages encrypted identity key material on disk.
type Keystore struct {
	path       string
	passphrase string
	mu         sync.Mutex
}

// keystoreFile is the JSON structure written to disk.
type keystoreFile struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`       // base64
	Nonce      string `json:"nonce"`      // base64
	Ciphertext string `json:"ciphertext"` // base64
	Tag        string `json:"tag"`        // base64
}

// storedIdentity is the plaintext representation of an identity key pair, plus
// an optional persisted domain countersignature (so it is reused across
// re-registration rather than regenerated — which is what lets it survive a
// later authority-key rotation).
type storedIdentity struct {
	Ed25519Public  string `json:"ed25519_public"`  // base64
	Ed25519Private string `json:"ed25519_private"` // base64
	X25519Public   string `json:"x25519_public"`   // base64
	X25519Private  string `json:"x25519_private"`  // base64
	DeviceID       string `json:"device_id"`       // base64
	CreatedAt      int64  `json:"created_at"`      // Unix seconds
}

// New creates a Keystore backed by the file at path. The passphrase is used
// to derive the encryption key. The file is created on first write.
func New(path, passphrase string) *Keystore {
	return &Keystore{
		path:       path,
		passphrase: passphrase,
	}
}

// Store saves an identity key pair under the given address. If the keystore
// file already exists, it is decrypted, updated, and re-encrypted.
func (ks *Keystore) Store(address string, kp *identity.IdentityKeyPair) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	identities, err := ks.loadAll()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if identities == nil {
		identities = make(map[string]storedIdentity)
	}

	identities[address] = storedIdentity{
		Ed25519Public:  base64.StdEncoding.EncodeToString(kp.Ed25519Public),
		Ed25519Private: base64.StdEncoding.EncodeToString(kp.Ed25519Private),
		X25519Public:   base64.StdEncoding.EncodeToString(kp.X25519Public[:]),
		X25519Private:  base64.StdEncoding.EncodeToString(kp.X25519Private[:]),
		DeviceID:       base64.StdEncoding.EncodeToString(kp.DeviceID[:]),
		CreatedAt:      kp.CreatedAt.Unix(),
	}

	return ks.saveAll(identities)
}

// Load retrieves an identity key pair by address. Returns ErrNotFound if
// the address is not in the keystore.
func (ks *Keystore) Load(address string) (*identity.IdentityKeyPair, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	identities, err := ks.loadAll()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	stored, ok := identities[address]
	if !ok {
		return nil, ErrNotFound
	}

	return stored.toKeyPair()
}

// List returns all addresses stored in the keystore.
func (ks *Keystore) List() ([]string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	identities, err := ks.loadAll()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	addrs := make([]string, 0, len(identities))
	for addr := range identities {
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// loadAll decrypts and deserializes all identities from the keystore file.
func (ks *Keystore) loadAll() (map[string]storedIdentity, error) {
	data, err := os.ReadFile(ks.path)
	if err != nil {
		return nil, err
	}

	var kf keystoreFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("keystore: invalid file format: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(kf.Salt)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(kf.Nonce)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(kf.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode ciphertext: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(kf.Tag)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode tag: %w", err)
	}

	key, err := crypto.DeriveKey([]byte(ks.passphrase), salt, hkdfInfo, crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("keystore: derive key: %w", err)
	}

	plaintext, err := crypto.AESGCMDecrypt(key, nonce, ciphertext, tag)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	var identities map[string]storedIdentity
	if err := json.Unmarshal(plaintext, &identities); err != nil {
		return nil, fmt.Errorf("keystore: unmarshal identities: %w", err)
	}

	return identities, nil
}

// saveAll encrypts and writes all identities to the keystore file.
func (ks *Keystore) saveAll(identities map[string]storedIdentity) error {
	plaintext, err := json.Marshal(identities)
	if err != nil {
		return fmt.Errorf("keystore: marshal identities: %w", err)
	}

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("keystore: generate salt: %w", err)
	}

	key, err := crypto.DeriveKey([]byte(ks.passphrase), salt, hkdfInfo, crypto.AES256KeySize)
	if err != nil {
		return fmt.Errorf("keystore: derive key: %w", err)
	}

	nonce, ciphertext, tag, err := crypto.AESGCMEncrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("keystore: encrypt: %w", err)
	}

	kf := keystoreFile{
		Version:    1,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Tag:        base64.StdEncoding.EncodeToString(tag),
	}

	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("keystore: marshal file: %w", err)
	}

	if err := os.WriteFile(ks.path, data, 0600); err != nil {
		return fmt.Errorf("keystore: write file: %w", err)
	}

	return nil
}

// toKeyPair converts a storedIdentity back to an IdentityKeyPair.
func (s *storedIdentity) toKeyPair() (*identity.IdentityKeyPair, error) {
	edPub, err := base64.StdEncoding.DecodeString(s.Ed25519Public)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode ed25519 public: %w", err)
	}
	edPriv, err := base64.StdEncoding.DecodeString(s.Ed25519Private)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode ed25519 private: %w", err)
	}
	xPub, err := base64.StdEncoding.DecodeString(s.X25519Public)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode x25519 public: %w", err)
	}
	xPriv, err := base64.StdEncoding.DecodeString(s.X25519Private)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode x25519 private: %w", err)
	}
	deviceID, err := base64.StdEncoding.DecodeString(s.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode device ID: %w", err)
	}

	kp := &identity.IdentityKeyPair{
		Ed25519Public:  ed25519.PublicKey(edPub),
		Ed25519Private: ed25519.PrivateKey(edPriv),
		CreatedAt:      time.Unix(s.CreatedAt, 0).UTC(),
	}
	copy(kp.X25519Public[:], xPub)
	copy(kp.X25519Private[:], xPriv)
	copy(kp.DeviceID[:], deviceID)

	return kp, nil
}
