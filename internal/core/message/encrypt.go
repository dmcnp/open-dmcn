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

const (
	// cekWrapLabelV1 is the original CEK-wrap HKDF info: a bare constant. It binds the derived
	// key-wrapping key to nothing about who it was derived for.
	cekWrapLabelV1 = "dmcn-cek-wrap-v1"
	// cekWrapLabelV2 labels the context-bound derivation in cekWrapInfoV2.
	cekWrapLabelV2 = "dmcn-cek-wrap-v2"
)

// KDF identifies a wrap's key-derivation generation, mirrored on the wire as
// RecipientRecord.kdf. See proto/core/message.proto for the normative definition.
//
// The rule that makes this work without any compatibility branch: ABSENT (0) MEANS 1. Every wrap
// written before the field existed used generation 1, and stored envelopes are never
// re-encrypted, so that mapping is permanent rather than transitional.
const (
	// KDFv1 derives the key-wrapping key from a bare label and seals the split blobs with no
	// additional data. It binds nothing about who the key was derived for.
	KDFv1 uint32 = 1
	// KDFv2 binds the derivation to the ephemeral and recipient keys (RFC 9180 kem_context) and
	// seals the header and body blobs under distinct AEAD labels.
	KDFv2 uint32 = 2
)

// producerKDF is the generation new wraps are written with. Readers dispatch on the value each
// record carries, so this only decides what we emit.
const producerKDF = KDFv2

// normalizeKDF applies the absent-means-1 rule.
func normalizeKDF(v uint32) uint32 {
	if v == 0 {
		return KDFv1
	}
	return v
}

// cekWrapInfoV1 is the legacy derivation context: the label alone.
func cekWrapInfoV1() []byte { return []byte(cekWrapLabelV1) }

// cekWrapInfoV2 binds the key-wrapping key to the two keys it was derived for, mirroring
// RFC 9180 section 4.1 DHKEM's kem_context = concat(enc, pkRm) — enc being the sender's
// ephemeral public key and pkRm the recipient's.
//
// Concatenation is unambiguous only because both are fixed 32-byte keys, which is why wrapCEK
// and unwrapCEK check the widths themselves rather than trusting the parser to have run.
//
// Deliberately no message ID and no transcript: wrapCEK is shared with SealedBlob, which has no
// message, and the envelope fields worth binding (message_id, created_at) are exactly the ones
// relay.MailboxStore drops, so binding them would make stored mail unreadable.
// cekWrapInfo returns the HKDF info for a generation, or an error for one this build does not
// know. Refusing an unknown generation is deliberate: a reader that cannot reproduce the
// derivation must say so rather than fall back and appear to fail authentication.
func cekWrapInfo(kdf uint32, ephPub, rcptPub [32]byte) ([]byte, error) {
	switch normalizeKDF(kdf) {
	case KDFv1:
		return cekWrapInfoV1(), nil
	case KDFv2:
		return cekWrapInfoV2(ephPub, rcptPub), nil
	default:
		return nil, fmt.Errorf("message: unknown CEK-wrap derivation %d", kdf)
	}
}

func cekWrapInfoV2(ephPub, rcptPub [32]byte) []byte {
	info := make([]byte, 0, len(cekWrapLabelV2)+64)
	info = append(info, cekWrapLabelV2...)
	info = append(info, ephPub[:]...)
	info = append(info, rcptPub[:]...)
	return info
}

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
	KDF           uint32   // derivation generation; 0 on the wire means KDFv1
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
	cek, err := unwrapCEK(rec, recipientPrivKey, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap CEK: %v", ErrDecryptionFailed, err)
	}

	// Decrypt payload
	padded, err := crypto.AESGCMDecrypt(cek, env.PayloadNonce[:], env.EncryptedPayload, env.PayloadTag[:])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrDecryptionFailed, err)
	}

	// Unpad payload
	payload, err := unpadPayload(padded)
	if err != nil {
		return nil, err
	}

	// Deserialize SignedMessage
	pb := &dmcnpb.SignedMessage{}
	if err := proto.Unmarshal(payload, pb); err != nil {
		return nil, fmt.Errorf("%w: unmarshal: %v", ErrDecryptionFailed, err)
	}

	sm := signedMessageFromProto(pb)

	// Verify here rather than leaving it to the caller. DecryptHeader (the split format) already
	// verifies internally, and a decrypt that returns unauthenticated plaintext with nothing in
	// the type system marking it as such is the kind of thing a later caller forgets.
	if err := sm.Verify(); err != nil {
		return nil, fmt.Errorf("%w: sender signature: %v", ErrDecryptionFailed, err)
	}

	// The envelope's own copies of these sit outside the sender signature, so a relay can
	// rewrite them freely. Cross-check them against the signed payload.
	//
	// Only when present: an envelope rebuilt from a mailbox entry carries neither (MailboxStore
	// persists MailboxEntry/MailboxBody, which have no message_id or created_at), so absent is
	// not a mismatch.
	if env.MessageID != ([16]byte{}) && env.MessageID != sm.Plaintext.MessageID {
		return nil, fmt.Errorf("%w: envelope message ID does not match the signed payload", ErrDecryptionFailed)
	}
	if env.CreatedAt != 0 && env.CreatedAt != sm.Plaintext.SentAt.Unix() {
		return nil, fmt.Errorf("%w: envelope created_at does not match the signed payload", ErrDecryptionFailed)
	}

	return sm, nil
}

// wrapCEK wraps the CEK for a single recipient using the KEM pattern:
// 1. Generate ephemeral X25519 key pair
// 2. X25519 shared secret = ephemeral_priv × recipient_x25519_pub
// 3. KWK = HKDF-SHA256(shared_secret, salt=nil, info) — see cekWrapInfoV1/V2
// 4. AES-256-GCM encrypt CEK with KWK
func wrapCEK(cek []byte, recipient RecipientInfo) (RecipientRecord, error) {
	// An all-zero recipient key would make the derivation context ambiguous and the DH
	// meaningless. X25519 rejects it as a low-order point too; this is the clearer error.
	if recipient.X25519Pub == ([32]byte{}) {
		return RecipientRecord{}, errors.New("wrap CEK: recipient X25519 key is all zero")
	}

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

	// Derive key-wrapping key. Salt is nil, matching the browser's `new Uint8Array(0)` — both
	// become 32 zero bytes per RFC 5869 section 2.2. That equivalence is load-bearing parity:
	// change either side and Go and the browser derive different keys.
	info, err := cekWrapInfo(producerKDF, ephPub, recipient.X25519Pub)
	if err != nil {
		return RecipientRecord{}, err
	}
	kwk, err := crypto.DeriveKey(shared[:], nil, info, crypto.AES256KeySize)
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
		KDF:           producerKDF,
	}
	copy(rec.CEKNonce[:], nonce)
	copy(rec.CEKTag[:], tag)

	return rec, nil
}

// unwrapCEK unwraps the CEK from a recipient record using the recipient's X25519 private key.
//
// recipientPubKey is the READER'S OWN public key, not rec.RecipientXPub. The v2 derivation binds
// the key-wrapping key to the recipient it was sealed for, and taking that value from the record
// would bind it to a field the sender chose instead of one the reader knows. Callers that select
// a record by matching rec.RecipientXPub pass an equal value; OpenSealed's try-every-record
// fallback deliberately does not.
//
// The record states its own derivation generation (RecipientRecord.kdf, absent meaning 1), so
// this dispatches rather than guessing. No trial decryption: an implementation reading this
// format needs one field, not a catalogue of derivations to attempt in order.
func unwrapCEK(rec *RecipientRecord, recipientPrivKey, recipientPubKey [32]byte) ([]byte, error) {
	if rec.EphemeralXPub == ([32]byte{}) {
		return nil, errors.New("unwrap CEK: ephemeral X25519 key is all zero")
	}

	info, err := cekWrapInfo(rec.KDF, rec.EphemeralXPub, recipientPubKey)
	if err != nil {
		return nil, err
	}

	// Compute shared secret
	shared, err := crypto.X25519SharedSecret(recipientPrivKey, rec.EphemeralXPub)
	if err != nil {
		return nil, fmt.Errorf("key exchange: %w", err)
	}

	kwk, err := crypto.DeriveKey(shared[:], nil, info, crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive KWK: %w", err)
	}
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
//
// The 4-byte length prefix lives INSIDE the AEAD, so by the time this runs the bytes are
// authenticated: a malformed prefix means the caller opened something padPayload did not
// produce — a bug or a format mismatch, never attacker input. Return an error rather than the
// padded buffer, because handing padding back as payload turns a local mistake into a protobuf
// decode failure somewhere far away.
func unpadPayload(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, fmt.Errorf("%w: padded payload is %d bytes, shorter than its length prefix", ErrDecryptionFailed, len(padded))
	}

	actualLen := uint32(padded[0])<<24 | uint32(padded[1])<<16 | uint32(padded[2])<<8 | uint32(padded[3])
	if uint64(actualLen)+4 > uint64(len(padded)) {
		return nil, fmt.Errorf("%w: padded length prefix %d exceeds the %d-byte buffer", ErrDecryptionFailed, actualLen, len(padded))
	}

	return padded[4 : 4+actualLen], nil
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
			Kdf:           r.KDF,
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
	for _, f := range []struct {
		dst, src []byte
		name     string
	}{
		{env.MessageID[:], pb.MessageId, "message_id"},
		{env.PayloadNonce[:], pb.PayloadNonce, "payload_nonce"},
		{env.PayloadTag[:], pb.PayloadTag, "payload_tag"},
		{env.RatchetPubKey[:], pb.RatchetPubKey, "ratchet_pub_key"},
	} {
		if err := fixedField(f.dst, f.src, f.name); err != nil {
			return nil, err
		}
	}

	if len(pb.EncryptedHeader) > 0 {
		env.EncryptedHeader = pb.EncryptedHeader
		env.HeaderSizeClass = pb.HeaderSizeClass
		env.EncryptedBody = pb.EncryptedBody
		env.BodySizeClass = pb.BodySizeClass
		env.BodyContentAddress = pb.BodyContentAddress
		for _, f := range []struct {
			dst, src []byte
			name     string
		}{
			{env.HeaderNonce[:], pb.HeaderNonce, "header_nonce"},
			{env.HeaderTag[:], pb.HeaderTag, "header_tag"},
			{env.BodyNonce[:], pb.BodyNonce, "body_nonce"},
			{env.BodyTag[:], pb.BodyTag, "body_tag"},
		} {
			if err := fixedField(f.dst, f.src, f.name); err != nil {
				return nil, err
			}
		}
	}

	for i, r := range pb.Recipients {
		rec := RecipientRecord{
			WrappedCEK: r.WrappedCek,
			KDF:        r.Kdf,
		}
		for _, f := range []struct {
			dst, src []byte
			name     string
		}{
			{rec.DeviceID[:], r.DeviceId, "device_id"},
			{rec.RecipientXPub[:], r.RecipientXPub, "recipient_x_pub"},
			{rec.EphemeralXPub[:], r.EphemeralXPub, "ephemeral_x_pub"},
			{rec.CEKNonce[:], r.CekNonce, "cek_nonce"},
			{rec.CEKTag[:], r.CekTag, "cek_tag"},
		} {
			if err := fixedField(f.dst, f.src, f.name); err != nil {
				return nil, fmt.Errorf("recipient %d: %w", i, err)
			}
		}
		env.Recipients = append(env.Recipients, rec)
	}

	return env, nil
}

// fixedField copies src into the fixed-width dst, requiring src to be either absent or exactly
// len(dst) bytes.
//
// "Absent or exact" rather than "exact": an envelope rebuilt from a mailbox entry legitimately
// carries no message_id, payload_nonce, payload_tag or ratchet_pub_key — relay.MailboxStore
// persists MailboxEntry/MailboxBody, which do not hold them — so demanding an exact length would
// reject every stored message. Absent stays absent, which the reader already handles: an
// all-zero recipient or ephemeral key is rejected outright in wrapCEK/unwrapCEK.
//
// What this does reject is the silent truncate-or-zero-pad that a bare copy() performed on
// attacker-controlled network input, where a 31-byte recipient key became a different,
// zero-padded 32-byte key.
func fixedField(dst, src []byte, name string) error {
	if len(src) == 0 {
		return nil
	}
	if len(src) != len(dst) {
		return fmt.Errorf("message: envelope: %s must be %d bytes, got %d", name, len(dst), len(src))
	}
	copy(dst, src)
	return nil
}

// EnvelopeRatchetPubKeyIsZero checks that the RatchetPubKey field is
// all zero bytes, as required for protocol v1.
func (e *EncryptedEnvelope) EnvelopeRatchetPubKeyIsZero() bool {
	return bytes.Equal(e.RatchetPubKey[:], make([]byte, 32))
}
