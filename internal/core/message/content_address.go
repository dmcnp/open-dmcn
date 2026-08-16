package message

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// ErrBodyAddressMismatch means a decrypted body does not match the content
// address committed in the (signed) header — the body was tampered with,
// swapped, or mis-addressed. Distinct from ErrBodyHashMismatch (the plaintext
// commitment): this one is the ciphertext-blob commitment.
var ErrBodyAddressMismatch = errors.New("message: body does not match content address")

// bodyBlob is the canonical content-addressed body blob: the full AEAD message
// body_nonce || encrypted_body || body_tag. Identical bytes across all recipients
// of one send (one CEK, one nonce), which is what makes keyless dedup possible.
func bodyBlob(nonce, ciphertext, tag []byte) []byte {
	blob := make([]byte, 0, len(nonce)+len(ciphertext)+len(tag))
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)
	blob = append(blob, tag...)
	return blob
}

// ComputeBodyContentAddress returns the content address of a body blob as a
// CIDv1 with the raw codec and a SHA-256 multihash (36 bytes):
//
//	0x01 0x55 0x12 0x20 || SHA-256(body_nonce || encrypted_body || body_tag)
//
// The raw codec marks a single-blob leaf; a future Merkle-DAG (chunked) body
// would use a dag-* codec in the same field with no wire change. The address is
// keyless — any node can recompute and verify it without the CEK.
func ComputeBodyContentAddress(nonce, ciphertext, tag []byte) ([]byte, error) {
	h := crypto.SHA256Hash(bodyBlob(nonce, ciphertext, tag))
	mh, err := multihash.Encode(h[:], multihash.SHA2_256)
	if err != nil {
		return nil, fmt.Errorf("message: content address: %w", err)
	}
	return cid.NewCidV1(cid.Raw, mh).Bytes(), nil
}

// BodyBlob returns the envelope's canonical body blob. Meaningful only for split
// envelopes; for a non-split envelope the body fields are zero.
func (e *EncryptedEnvelope) BodyBlob() []byte {
	return bodyBlob(e.BodyNonce[:], e.EncryptedBody, e.BodyTag[:])
}

// bodyAddressMatches reports whether addr is the content address of this
// envelope's body blob.
func (e *EncryptedEnvelope) bodyAddressMatches(addr []byte) (bool, error) {
	got, err := ComputeBodyContentAddress(e.BodyNonce[:], e.EncryptedBody, e.BodyTag[:])
	if err != nil {
		return false, err
	}
	return bytes.Equal(got, addr), nil
}

// recognizedBodyCID reports whether b is a content address this code knows how to
// verify (CIDv1 / raw codec / SHA-256). Anything else — including a future DAG
// codec or hash algorithm — is treated as unrecognized so keyless verification
// can fail open and stay forward-compatible.
func recognizedBodyCID(b []byte) bool {
	c, err := cid.Cast(b)
	if err != nil {
		return false
	}
	p := c.Prefix()
	return p.Version == 1 && p.Codec == cid.Raw && p.MhType == multihash.SHA2_256
}

// VerifyBodyContentAddress recomputes the body blob's content address and checks
// it against the cleartext address carried on the envelope. It is KEYLESS — a
// relay can call it without the CEK.
//
// It FAILS OPEN: a non-split envelope, or one with no (or an unrecognized)
// cleartext address, returns nil. body_hash and the AEAD tag remain the
// authoritative integrity checks; this is a defense-in-depth + dedup-correctness
// optimization for intermediaries. A present, recognized, but WRONG address
// returns ErrBodyAddressMismatch (fail-closed when the address is one we can
// check).
func (e *EncryptedEnvelope) VerifyBodyContentAddress() error {
	if !e.IsSplit() || len(e.BodyContentAddress) == 0 || !recognizedBodyCID(e.BodyContentAddress) {
		return nil
	}
	ok, err := e.bodyAddressMatches(e.BodyContentAddress)
	if err != nil {
		return err
	}
	if !ok {
		return ErrBodyAddressMismatch
	}
	return nil
}
