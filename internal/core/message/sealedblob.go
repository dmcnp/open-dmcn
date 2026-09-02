package message

import (
	"errors"
	"fmt"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// SealedBlob is arbitrary plaintext encrypted under a random CEK (AES-256-GCM),
// with the CEK wrapped to one or more X25519 recipients using the same KEM as the
// message envelope (X25519 ECDH + HKDF-SHA256 + AES-256-GCM). Any single recipient
// private key opens it.
//
// It is the mechanism behind the recipient mail-filter list (P5 of the
// domain-anchored plan): the list is sealed to BOTH the recipient's identity
// X25519 key (so the owner reads/edits it on any device) AND the mailbox/relay's
// X25519 key (so the mailbox can decrypt it to silently drop blocked senders at
// STORE). The server only ever stores/returns this ciphertext. JSON-encodable so
// the browser can hold the owner-wrapped copy and decrypt with Web Crypto.
type SealedBlob struct {
	Nonce      []byte            `json:"nonce"`      // 12-byte AES-GCM nonce over the payload
	Ciphertext []byte            `json:"ciphertext"` // AES-256-GCM ciphertext of the plaintext
	Tag        []byte            `json:"tag"`        // 16-byte AES-GCM auth tag
	Recipients []sealedRecipient `json:"recipients"` // per-recipient wrapped CEK
}

// sealedRecipient is one X25519-wrapped copy of the CEK.
type sealedRecipient struct {
	RecipientXPub []byte `json:"recipient_xpub"` // 32 bytes — identifies which recipient this wrap is for
	EphemeralXPub []byte `json:"ephemeral_xpub"` // 32 bytes — per-recipient ephemeral
	WrappedCEK    []byte `json:"wrapped_cek"`    // AES-256-GCM ciphertext of the CEK
	CEKNonce      []byte `json:"cek_nonce"`      // 12 bytes
	CEKTag        []byte `json:"cek_tag"`        // 16 bytes
	// KDF is the derivation generation, same meaning as RecipientRecord.kdf: omitted means 1.
	// A sealed blob has no envelope and no version of its own, so the wrap carries it here for
	// the same reason it rides the recipient record on the wire — it is what survives storage.
	KDF uint32 `json:"kdf,omitempty"`
}

// SealToRecipients encrypts plaintext under a fresh CEK and wraps that CEK to each
// recipient X25519 public key. Requires at least one recipient.
func SealToRecipients(plaintext []byte, recipients [][32]byte) (*SealedBlob, error) {
	if len(recipients) == 0 {
		return nil, errors.New("message: seal: no recipients")
	}
	cek, err := crypto.RandomBytes(crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("message: seal: cek: %w", err)
	}
	nonce, ct, tag, err := crypto.AESGCMEncrypt(cek, plaintext)
	if err != nil {
		return nil, fmt.Errorf("message: seal: encrypt: %w", err)
	}
	b := &SealedBlob{Nonce: nonce, Ciphertext: ct, Tag: tag}
	for _, rpub := range recipients {
		rec, err := wrapCEK(cek, RecipientInfo{X25519Pub: rpub})
		if err != nil {
			return nil, fmt.Errorf("message: seal: wrap: %w", err)
		}
		b.Recipients = append(b.Recipients, sealedRecipient{
			RecipientXPub: append([]byte{}, rec.RecipientXPub[:]...),
			EphemeralXPub: append([]byte{}, rec.EphemeralXPub[:]...),
			WrappedCEK:    rec.WrappedCEK,
			CEKNonce:      append([]byte{}, rec.CEKNonce[:]...),
			CEKTag:        append([]byte{}, rec.CEKTag[:]...),
			KDF:           rec.KDF,
		})
	}
	return b, nil
}

// OpenSealed decrypts a SealedBlob with one recipient's X25519 private+public key.
// It tries the recipient record matching pub first, then falls back to trying all
// records (an X25519 unwrap either authenticates via its GCM tag or fails, so a
// wrong record is rejected, not silently mis-decrypted).
func OpenSealed(b *SealedBlob, priv [32]byte, pub [32]byte) ([]byte, error) {
	if b == nil || len(b.Recipients) == 0 {
		return nil, errors.New("message: open: empty sealed blob")
	}
	for _, sr := range b.Recipients {
		// Take only an exact match. The earlier form guarded the comparison on len == 32, so a
		// record with a malformed pub was NOT skipped — it fell through and was tried here as
		// though it were ours. RecipientXPub is now an input to the KEM derivation, so a
		// malformed one must be left to the fallback rather than treated as a match.
		if len(sr.RecipientXPub) != 32 || [32]byte(sr.RecipientXPub) != pub {
			continue
		}
		if pt, err := tryOpen(b, &sr, priv, pub); err == nil {
			return pt, nil
		}
	}
	// Fallback: pub may not be recorded (e.g. caller passed a different key); try all.
	for _, sr := range b.Recipients {
		if pt, err := tryOpen(b, &sr, priv, pub); err == nil {
			return pt, nil
		}
	}
	return nil, errors.New("message: open: no recipient record opened with this key")
}

// tryOpen opens one recipient record. pub is the READER'S own public key and is passed through
// to unwrapCEK as the derivation context — never sr.RecipientXPub, which is whatever the sealer
// wrote and is exactly what this function's caller may be iterating past.
func tryOpen(b *SealedBlob, sr *sealedRecipient, priv, pub [32]byte) ([]byte, error) {
	rr := &RecipientRecord{WrappedCEK: sr.WrappedCEK, KDF: sr.KDF}
	copy(rr.RecipientXPub[:], sr.RecipientXPub)
	copy(rr.EphemeralXPub[:], sr.EphemeralXPub)
	copy(rr.CEKNonce[:], sr.CEKNonce)
	copy(rr.CEKTag[:], sr.CEKTag)
	cek, err := unwrapCEK(rr, priv, pub)
	if err != nil {
		return nil, err
	}
	return crypto.AESGCMDecrypt(cek, b.Nonce, b.Ciphertext, b.Tag)
}
