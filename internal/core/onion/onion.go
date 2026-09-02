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
const (
	// layerHKDFInfo is the original onion layer-key context: a bare label.
	layerHKDFInfo = "dmcn-onion-layer-v1"
	// layerHKDFInfoV2 labels the context-bound derivation in layerInfoV2.
	layerHKDFInfoV2 = "dmcn-onion-layer-v2"
)

// layerInfoV2 binds the layer key to the ephemeral and relay public keys, the same
// RFC 9180 kem_context shape the message CEK wrap uses (message.cekWrapInfoV2).
//
// This matters more here than the label alone suggests: a relay's static X25519 key serves BOTH
// this KEM and the SealedBlob KEM behind the mail filter, and until now the only thing keeping
// those two contexts apart was the pair of label constants.
func layerInfoV2(ephPub, relayPub [32]byte) []byte {
	info := make([]byte, 0, len(layerHKDFInfoV2)+64)
	info = append(info, layerHKDFInfoV2...)
	info = append(info, ephPub[:]...)
	info = append(info, relayPub[:]...)
	return info
}

// LayerKDF names an onion layer's key-derivation generation. It is carried by the packet's
// existing version field (OnionPacket.version), so a peeling relay dispatches on a declared
// value rather than trying derivations in turn — the same rule as RecipientRecord.kdf.
const (
	LayerKDFv1 uint32 = 1 // info = "dmcn-onion-layer-v1"; binds nothing
	LayerKDFv2 uint32 = 2 // info = "dmcn-onion-layer-v2" || eph_pub || relay_pub
)

// LayerInfo returns the HKDF info for a layer generation, or an error for one this build does
// not know. Unlike mail, onion packets are never stored, so nothing older than the deployed
// fleet is ever presented — there is no permanent legacy arm to carry here.
func LayerInfo(version uint32, ephPub, relayPub [32]byte) ([]byte, error) {
	switch version {
	case LayerKDFv1:
		return []byte(layerHKDFInfo), nil
	case LayerKDFv2:
		return layerInfoV2(ephPub, relayPub), nil
	default:
		return nil, fmt.Errorf("onion: unknown layer derivation %d", version)
	}
}

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
func SealLayer(relayPub [32]byte, plaintext []byte, version uint32) (*SealedLayer, error) {
	ephPub, ephPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("onion: ephemeral key: %w", err)
	}
	shared, err := crypto.X25519SharedSecret(ephPriv, relayPub)
	if err != nil {
		return nil, fmt.Errorf("onion: key exchange: %w", err)
	}
	info, err := LayerInfo(version, ephPub, relayPub)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveKey(shared[:], nil, info, crypto.AES256KeySize)
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
func OpenLayer(relayPriv [32]byte, sl *SealedLayer, version uint32) ([]byte, error) {
	shared, err := crypto.X25519SharedSecret(relayPriv, sl.EphemeralXPub)
	if err != nil {
		return nil, fmt.Errorf("onion: key exchange: %w", err)
	}

	// Generation 2 binds this relay's own public key, which the caller does not carry — relays
	// hold only the private half — so derive it. One scalar multiplication per layer open, and
	// only for the generation that needs it.
	var relayPub [32]byte
	if version == LayerKDFv2 {
		if relayPub, err = crypto.X25519PublicFromPrivate(relayPriv); err != nil {
			return nil, fmt.Errorf("onion: derive relay public key: %w", err)
		}
	}

	info, err := LayerInfo(version, sl.EphemeralXPub, relayPub)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveKey(shared[:], nil, info, crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("onion: derive layer key: %w", err)
	}
	pt, err := crypto.AESGCMDecrypt(key, sl.Nonce[:], sl.Ciphertext, sl.Tag[:])
	if err != nil {
		return nil, fmt.Errorf("onion: open layer: %w", err)
	}
	return pt, nil
}
