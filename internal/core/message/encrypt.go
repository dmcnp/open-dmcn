package message

import (
	"bytes"
	"errors"
	"fmt"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrRecipientNotFound is returned when the decrypting device's key is
	// not found in the envelope's recipient list.
	ErrRecipientNotFound = errors.New("message: recipient not found in envelope")
	// ErrDecryptionFailed is returned when authenticated decryption fails,
	// typically due to tampered ciphertext.
	ErrDecryptionFailed = errors.New("message: decryption failed")
)

// hkdfInfo is the domain separation string for HKDF key derivation
// when wrapping the CEK for each recipient.
var hkdfInfo = []byte("dmcn-cek-wrap-v1")

// sizeClasses defines the payload size class buckets for traffic analysis
// resistance. See SPEC.md §3.
var sizeClasses = []uint32{
	1024,        // 1 KB
	4 * 1024,    // 4 KB
	16 * 1024,   // 16 KB
	64 * 1024,   // 64 KB
	256 * 1024,  // 256 KB
	1024 * 1024, // 1 MB
}

// RecipientInfo holds the information needed to encrypt a message for
// a single recipient device.
type RecipientInfo struct {
	DeviceID  [16]byte
	X25519Pub [32]byte
}

// RecipientRecord holds the wrapped CEK for a single recipient device.
// See SPEC.md §3.
type RecipientRecord struct {
	DeviceID      [16]byte
	RecipientXPub [32]byte // X25519 public key of recipient device
	EphemeralXPub [32]byte // per-recipient ephemeral X25519 public key
	WrappedCEK    []byte   // AES-256-GCM ciphertext of CEK
	CEKNonce      [12]byte // 96-bit nonce for CEK wrapping
	CEKTag        [16]byte // GCM auth tag for CEK wrapping
}

// EncryptedEnvelope is the outer transport structure for encrypted messages.
// See SPEC.md §3.
type EncryptedEnvelope struct {
	Version          uint32
	MessageID        [16]byte
	Recipients       []RecipientRecord
	EncryptedPayload []byte   // AES-256-GCM ciphertext of SignedMessage
	PayloadNonce     [12]byte // 96-bit nonce for payload
	PayloadTag       [16]byte // GCM auth tag for payload
	PayloadSizeClass uint32   // padded size bucket
	CreatedAt        int64    // Unix seconds
	RatchetPubKey    [32]byte // reserved; zero in protocol v1

	// Split header/body format (additive). A non-empty EncryptedHeader means the
	// envelope carries a separable, independently-fetchable header and body (both
	// sealed with the same per-message CEK) instead of EncryptedPayload. See split.go.
	EncryptedHeader []byte
	HeaderNonce     [12]byte
	HeaderTag       [16]byte
	HeaderSizeClass uint32
	EncryptedBody   []byte
	BodyNonce       [12]byte
	BodyTag         [16]byte
	BodySizeClass   uint32
	// BodyContentAddress is the cleartext CIDv1(raw/sha2-256) of the body blob
	// (body_nonce||encrypted_body||body_tag). Set by EncryptSplit. Lets relays
	// verify body integrity and (later) key storage on it without the CEK; the
	// authoritative copy is the signed one in the header. Empty for non-split/v1.
	BodyContentAddress []byte
}

// IsSplit reports whether the envelope uses the separable header/body format.
func (e *EncryptedEnvelope) IsSplit() bool {
	return len(e.EncryptedHeader) > 0
}

// Encrypt produces an EncryptedEnvelope from a SignedMessage using the
// hybrid KEM pattern described in SPEC.md §3.
//
// The message is encrypted once with a randomly generated CEK. The CEK
// is then wrapped individually for each recipient device using X25519
// key exchange + HKDF-SHA256 + AES-256-GCM.
func Encrypt(msg *SignedMessage, recipients []RecipientInfo) (*EncryptedEnvelope, error) {
	if len(recipients) == 0 {
		return nil, errors.New("message: encrypt: at least one recipient required")
	}

	// Step 1: Serialize the SignedMessage
	pb := msg.toProto()
	payload, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("message: encrypt: marshal: %w", err)
	}

	// Step 2: Pad to size class bucket
	sizeClass := selectSizeClass(uint32(len(payload)))
	padded := padPayload(payload, sizeClass)

	// Step 3: Generate random 256-bit CEK
	cekBytes, err := crypto.RandomBytes(crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("message: encrypt: generate CEK: %w", err)
	}

	// Step 4: Encrypt padded payload with CEK
	payloadNonce, payloadCiphertext, payloadTag, err := crypto.AESGCMEncrypt(cekBytes, padded)
	if err != nil {
		return nil, fmt.Errorf("message: encrypt: payload: %w", err)
	}

	// Step 5: Wrap CEK for each recipient
	recipientRecords := make([]RecipientRecord, len(recipients))
	for i, r := range recipients {
		rec, err := wrapCEK(cekBytes, r)
		if err != nil {
			return nil, fmt.Errorf("message: encrypt: wrap CEK for recipient %d: %w", i, err)
		}
		recipientRecords[i] = rec
	}

	// Step 6: Assemble envelope
	env := &EncryptedEnvelope{
		Version:          1,
		MessageID:        msg.Plaintext.MessageID,
		Recipients:       recipientRecords,
		EncryptedPayload: payloadCiphertext,
		PayloadSizeClass: sizeClass,
		CreatedAt:        msg.Plaintext.SentAt.Unix(),
		// RatchetPubKey remains zero-valued for v1
	}
	copy(env.PayloadNonce[:], payloadNonce)
	copy(env.PayloadTag[:], payloadTag)

	return env, nil
}

// Decrypt decrypts an EncryptedEnvelope using the recipient's X25519 private key
// and device ID. Returns the SignedMessage inside.
//
// Returns ErrRecipientNotFound if the device's key is not in the recipient list.
// Returns ErrDecryptionFailed if the ciphertext has been tampered with.
//
// See SPEC.md §3.
func Decrypt(env *EncryptedEnvelope, recipientPrivKey [32]byte, recipientPubKey [32]byte) (*SignedMessage, error) {
	// Find the matching recipient record
	var rec *RecipientRecord
	for i := range env.Recipients {
		if env.Recipients[i].RecipientXPub == recipientPubKey {
			rec = &env.Recipients[i]
			break
		}
	}
	if rec == nil {
		return nil, ErrRecipientNotFound
	}

	// Unwrap CEK
	cek, err := unwrapCEK(rec, recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap CEK: %v", ErrDecryptionFailed, err)
	}

	// Decrypt payload
	padded, err := crypto.AESGCMDecrypt(cek, env.PayloadNonce[:], env.EncryptedPayload, env.PayloadTag[:])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrDecryptionFailed, err)
	}

	// Unpad payload
	payload := unpadPayload(padded)

	// Deserialize SignedMessage
	pb := &dmcnpb.SignedMessage{}
	if err := proto.Unmarshal(payload, pb); err != nil {
		return nil, fmt.Errorf("%w: unmarshal: %v", ErrDecryptionFailed, err)
	}

	return signedMessageFromProto(pb), nil
}

// wrapCEK wraps the CEK for a single recipient using the KEM pattern:
// 1. Generate ephemeral X25519 key pair
// 2. X25519 shared secret = ephemeral_priv × recipient_x25519_pub
// 3. KWK = HKDF-SHA256(shared_secret, nil, "dmcn-cek-wrap-v1")
// 4. AES-256-GCM encrypt CEK with KWK
func wrapCEK(cek []byte, recipient RecipientInfo) (RecipientRecord, error) {
	// Generate ephemeral key pair
	ephPub, ephPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return RecipientRecord{}, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Compute shared secret
	shared, err := crypto.X25519SharedSecret(ephPriv, recipient.X25519Pub)
	if err != nil {
		return RecipientRecord{}, fmt.Errorf("key exchange: %w", err)
	}

	// Derive key-wrapping key
	kwk, err := crypto.DeriveKey(shared[:], nil, hkdfInfo, crypto.AES256KeySize)
	if err != nil {
		return RecipientRecord{}, fmt.Errorf("derive KWK: %w", err)
	}

	// Encrypt CEK with KWK
	nonce, ciphertext, tag, err := crypto.AESGCMEncrypt(kwk, cek)
	if err != nil {
		return RecipientRecord{}, fmt.Errorf("wrap CEK: %w", err)
	}

	rec := RecipientRecord{
		DeviceID:      recipient.DeviceID,
		RecipientXPub: recipient.X25519Pub,
		EphemeralXPub: ephPub,
		WrappedCEK:    ciphertext,
	}
	copy(rec.CEKNonce[:], nonce)
	copy(rec.CEKTag[:], tag)

	return rec, nil
}

// unwrapCEK unwraps the CEK from a recipient record using the recipient's
// X25519 private key.
func unwrapCEK(rec *RecipientRecord, recipientPrivKey [32]byte) ([]byte, error) {
	// Compute shared secret
	shared, err := crypto.X25519SharedSecret(recipientPrivKey, rec.EphemeralXPub)
	if err != nil {
		return nil, fmt.Errorf("key exchange: %w", err)
	}

	// Derive key-wrapping key
	kwk, err := crypto.DeriveKey(shared[:], nil, hkdfInfo, crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive KWK: %w", err)
	}

	// Decrypt CEK
	cek, err := crypto.AESGCMDecrypt(kwk, rec.CEKNonce[:], rec.WrappedCEK, rec.CEKTag[:])
	if err != nil {
		return nil, fmt.Errorf("unwrap CEK: %w", err)
	}

	return cek, nil
}

// selectSizeClass returns the smallest size class that can hold the given payload.
func selectSizeClass(payloadSize uint32) uint32 {
	// padPayload prepends a 4-byte length prefix, so the bucket must fit
	// payloadSize+4 — otherwise a payload sized at (or within 4 bytes of) a class
	// boundary would have its tail truncated.
	needed := payloadSize + 4
	for _, sc := range sizeClasses {
		if needed <= sc {
			return sc
		}
	}
	// If larger than all classes, use actual size rounded up to nearest MB
	mb := uint32(1024 * 1024)
	return ((needed + mb - 1) / mb) * mb
}

// padPayload pads the payload to the target size class.
// Format: [4-byte big-endian actual length][payload][zero padding]
func padPayload(payload []byte, targetSize uint32) []byte {
	actualLen := uint32(len(payload))
	padded := make([]byte, targetSize)

	// Store actual length as 4-byte big-endian prefix
	padded[0] = byte(actualLen >> 24)
	padded[1] = byte(actualLen >> 16)
	padded[2] = byte(actualLen >> 8)
	padded[3] = byte(actualLen)

	copy(padded[4:], payload)
	// Remaining bytes are already zero

	return padded
}

// unpadPayload removes padding and returns the original payload.
func unpadPayload(padded []byte) []byte {
	if len(padded) < 4 {
		return padded
	}

	actualLen := uint32(padded[0])<<24 | uint32(padded[1])<<16 | uint32(padded[2])<<8 | uint32(padded[3])
	if int(actualLen)+4 > len(padded) {
		return padded
	}

	return padded[4 : 4+actualLen]
}

// ToProto converts an EncryptedEnvelope to its protobuf representation.
func (e *EncryptedEnvelope) ToProto() *dmcnpb.EncryptedEnvelope {
	pb := &dmcnpb.EncryptedEnvelope{
		Version:          e.Version,
		MessageId:        e.MessageID[:],
		EncryptedPayload: e.EncryptedPayload,
		PayloadNonce:     e.PayloadNonce[:],
		PayloadTag:       e.PayloadTag[:],
		PayloadSizeClass: e.PayloadSizeClass,
		CreatedAt:        e.CreatedAt,
		RatchetPubKey:    e.RatchetPubKey[:],
	}

	for _, r := range e.Recipients {
		pb.Recipients = append(pb.Recipients, &dmcnpb.RecipientRecord{
			DeviceId:      r.DeviceID[:],
			RecipientXPub: r.RecipientXPub[:],
			EphemeralXPub: r.EphemeralXPub[:],
			WrappedCek:    r.WrappedCEK,
			CekNonce:      r.CEKNonce[:],
			CekTag:        r.CEKTag[:],
		})
	}

	if e.IsSplit() {
		pb.EncryptedHeader = e.EncryptedHeader
		pb.HeaderNonce = e.HeaderNonce[:]
		pb.HeaderTag = e.HeaderTag[:]
		pb.HeaderSizeClass = e.HeaderSizeClass
		pb.EncryptedBody = e.EncryptedBody
		pb.BodyNonce = e.BodyNonce[:]
		pb.BodyTag = e.BodyTag[:]
		pb.BodySizeClass = e.BodySizeClass
		pb.BodyContentAddress = e.BodyContentAddress
	}

	return pb
}

// EncryptedEnvelopeFromProto converts a protobuf EncryptedEnvelope to the Go type.
func EncryptedEnvelopeFromProto(pb *dmcnpb.EncryptedEnvelope) (*EncryptedEnvelope, error) {
	if pb == nil {
		return nil, errors.New("message: nil protobuf envelope")
	}

	env := &EncryptedEnvelope{
		Version:          pb.Version,
		EncryptedPayload: pb.EncryptedPayload,
		PayloadSizeClass: pb.PayloadSizeClass,
		CreatedAt:        pb.CreatedAt,
	}
	copy(env.MessageID[:], pb.MessageId)
	copy(env.PayloadNonce[:], pb.PayloadNonce)
	copy(env.PayloadTag[:], pb.PayloadTag)
	copy(env.RatchetPubKey[:], pb.RatchetPubKey)

	if len(pb.EncryptedHeader) > 0 {
		env.EncryptedHeader = pb.EncryptedHeader
		copy(env.HeaderNonce[:], pb.HeaderNonce)
		copy(env.HeaderTag[:], pb.HeaderTag)
		env.HeaderSizeClass = pb.HeaderSizeClass
		env.EncryptedBody = pb.EncryptedBody
		copy(env.BodyNonce[:], pb.BodyNonce)
		copy(env.BodyTag[:], pb.BodyTag)
		env.BodySizeClass = pb.BodySizeClass
		env.BodyContentAddress = pb.BodyContentAddress
	}

	for _, r := range pb.Recipients {
		rec := RecipientRecord{
			WrappedCEK: r.WrappedCek,
		}
		copy(rec.DeviceID[:], r.DeviceId)
		copy(rec.RecipientXPub[:], r.RecipientXPub)
		copy(rec.EphemeralXPub[:], r.EphemeralXPub)
		copy(rec.CEKNonce[:], r.CekNonce)
		copy(rec.CEKTag[:], r.CekTag)
		env.Recipients = append(env.Recipients, rec)
	}

	return env, nil
}

// EnvelopeRatchetPubKeyIsZero checks that the RatchetPubKey field is
// all zero bytes, as required for protocol v1.
func (e *EncryptedEnvelope) EnvelopeRatchetPubKeyIsZero() bool {
	return bytes.Equal(e.RatchetPubKey[:], make([]byte, 32))
}
