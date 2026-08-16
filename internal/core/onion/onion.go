// Package onion implements the per-hop encryption primitive for DMCN onion
// routing: each layer is sealed to a relay's X25519 key with an ephemeral
// X25519 ECDH → HKDF-SHA256 → AES-256-GCM, the same KEM/DEM scheme the message
// layer uses to wrap a CEX (internal/core/message wrapCEK). A relay opens its
// layer with its X25519 private key to recover the next hop + inner payload.
package onion

import (
	"fmt"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// layerHKDFInfo domain-separates onion-layer key derivation from every other
// HKDF use in the protocol.
const layerHKDFInfo = "dmcn-onion-layer-v1"

// SealedLayer is one onion layer: a payload encrypted to a single relay's
// X25519 key, plus the ephemeral public key the relay needs to derive the
// shared secret.
type SealedLayer struct {
	EphemeralXPub [32]byte
	Nonce         [12]byte
	Ciphertext    []byte
	Tag           [16]byte
}

// SealLayer encrypts plaintext to relayPub. A fresh ephemeral X25519 keypair is
// generated per call (single-use), so layers are unlinkable across hops.
func SealLayer(relayPub [32]byte, plaintext []byte) (*SealedLayer, error) {
	ephPub, ephPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("onion: ephemeral key: %w", err)
	}
	shared, err := crypto.X25519SharedSecret(ephPriv, relayPub)
	if err != nil {
		return nil, fmt.Errorf("onion: key exchange: %w", err)
	}
	key, err := crypto.DeriveKey(shared[:], nil, []byte(layerHKDFInfo), crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("onion: derive layer key: %w", err)
	}
	nonce, ciphertext, tag, err := crypto.AESGCMEncrypt(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("onion: seal layer: %w", err)
	}
	sl := &SealedLayer{Ciphertext: ciphertext}
	copy(sl.EphemeralXPub[:], ephPub[:])
	copy(sl.Nonce[:], nonce)
	copy(sl.Tag[:], tag)
	return sl, nil
}

// OpenLayer decrypts a sealed layer with the relay's X25519 private key,
// recovering the plaintext (the next hop instruction + inner payload). A wrong
// key or any tampering fails the AEAD authentication.
func OpenLayer(relayPriv [32]byte, sl *SealedLayer) ([]byte, error) {
	shared, err := crypto.X25519SharedSecret(relayPriv, sl.EphemeralXPub)
	if err != nil {
		return nil, fmt.Errorf("onion: key exchange: %w", err)
	}
	key, err := crypto.DeriveKey(shared[:], nil, []byte(layerHKDFInfo), crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("onion: derive layer key: %w", err)
	}
	pt, err := crypto.AESGCMDecrypt(key, sl.Nonce[:], sl.Ciphertext, sl.Tag[:])
	if err != nil {
		return nil, fmt.Errorf("onion: open layer: %w", err)
	}
	return pt, nil
}
