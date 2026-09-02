package message

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"google.golang.org/protobuf/proto"
)

// ctxMsgHeader domain-separates the header signature from any other signature.
const ctxMsgHeader = "dmcn-msg-header-v1\x00"

// snippetMax is how many bytes of a text body are previewed in the header.
const snippetMax = 140

// aadHeaderV1 and aadBodyV1 are the AEAD additional-data labels distinguishing the two blobs a
// split envelope seals under ONE CEK.
//
// Be honest about what they buy: hygiene, not a vulnerability fix. Header and body share a CEK
// and differ only by nonce, so without a label a relay can serve the header blob where the body
// belongs and it AEAD-opens successfully, failing later on body_hash. The labels move that
// rejection to the AEAD, where it belongs. Nothing leaks either way, and body_hash already
// catches it unconditionally.
//
// They are NOT a defence against surreptitious forwarding. AAD is authenticated under the CEK,
// and that adversary is a legitimate recipient who HOLDS the CEK: they can re-seal the identical
// header plaintext under any AAD they choose, and the sender's Ed25519 signature — which covers
// the header plaintext, not its ciphertext — still verifies. What catches that is a reader
// checking the signed recipient address; see MessageHeader.AddressedToKey.
//
// These are constants on purpose. Anything derived from the envelope risks binding a field that
// relay.MailboxStore does not persist, which would make stored mail unreadable — see
// crypto.AESGCMEncryptAAD.
const (
	aadHeaderV1 = "dmcn-aad-hdr-v1\x00"
	aadBodyV1   = "dmcn-aad-body-v1\x00"
)

// headerAAD and bodyAAD return the additional data for a given derivation generation.
//
// They key off the SAME value the recipient record carries, so an envelope's blobs and its wraps
// can never disagree: a reader unwraps the CEK, learns the generation from the record it used,
// and opens the blobs with the matching data. Generation 1 predates the labels and used none.
func headerAAD(kdf uint32) []byte { return sealAAD(kdf, aadHeaderV1) }
func bodyAAD(kdf uint32) []byte   { return sealAAD(kdf, aadBodyV1) }

func sealAAD(kdf uint32, label string) []byte {
	if normalizeKDF(kdf) == KDFv1 {
		return nil
	}
	return []byte(label)
}

// ErrBodyHashMismatch means a fetched body does not match the (signed) header's
// commitment — the body was tampered with or swapped.
var ErrBodyHashMismatch = errors.New("message: body does not match header body_hash")

// MessageHeader is the small, previewable part of a message: who/what/when plus a
// commitment to the body. Signed independently so a recipient can trust an inbox
// preview without downloading the body.
type MessageHeader struct {
	Version          uint32
	MessageID        [16]byte
	ThreadID         [16]byte
	SenderAddress    string
	SenderPublicKey  ed25519.PublicKey
	RecipientAddress string
	SentAt           time.Time
	Subject          string
	AttachmentCount  uint32
	BodySize         uint64
	Snippet          string
	ReplyToID        [16]byte
	BodyHash         [32]byte
	// BodyContentAddress is the CIDv1(raw/sha2-256) of the body ciphertext blob.
	// Set by EncryptSplit and covered by the header signature, so a verified header
	// commits to the exact ciphertext. Empty for pre-feature / non-split messages.
	BodyContentAddress []byte
	// To/Cc are the full recipient lists, identical across all recipients' copies
	// and visible to everyone. Bcc is populated only on the sender's own Sent
	// self-copy; every recipient copy carries an empty Bcc so a Bcc recipient is
	// never revealed. All three are covered by the header signature.
	To  []string
	Cc  []string
	Bcc []string
	// SenderDisplay is an optional human-readable name for the sender — legacy
	// mail's From display name, which a bridge would otherwise discard. Covered by
	// the header signature, so no relay can rewrite it, but it is NOT an identity:
	// whoever signed the header asserted it. Readers must render it only alongside
	// SenderAddress and must never key trust decisions on it. Empty = none, and an
	// empty value marshals identically to a header predating the field.
	SenderDisplay string
}

// SignedHeader wraps a MessageHeader with the sender's signature (which covers
// BodyHash, so a verified header also authenticates the eventual body).
type SignedHeader struct {
	Header          MessageHeader
	SenderSignature [64]byte
}

// Audience returns every address this header names as a recipient: the per-copy
// recipient_address followed by the visible To and Cc lists.
//
// Bcc is deliberately excluded. It is populated only on the sender's own Sent self-copy, so
// including it would make a Sent copy look "addressed to" people no recipient copy names.
func (h *MessageHeader) Audience() []string {
	out := make([]string, 0, 1+len(h.To)+len(h.Cc))
	if h.RecipientAddress != "" {
		out = append(out, h.RecipientAddress)
	}
	out = append(out, h.To...)
	out = append(out, h.Cc...)
	return out
}

// AddressedToKey reports whether the sender addressed this message to the mailbox now reading
// it: whether any address in the signed audience resolves to mailboxKey.
//
// WHY THIS EXISTS. It is the check that detects surreptitious forwarding — the one thing the
// envelope's AEAD cannot do. A legitimate recipient holds the CEK, so it can re-seal a message's
// header and body to a third party and the sender's signature still verifies; no additional
// authenticated data helps, because that data is authenticated under the very key the attacker
// holds. What an attacker CANNOT do is change recipient_address, to or cc, which the sender
// signed. So the reader compares them against itself.
//
// WHY KEYED ON THE MAILBOX, NOT THE ADDRESS. Mailboxes are keyed by X25519 public key, and
// address aliases share a keypair with their canonical address — so mail sent to sales@example
// legitimately lands in the mailbox its owner reads as me@example. Comparing address strings
// would report an account's own mail as misaddressed, and getting it right that way would mean
// consulting an operator-signed alias marker, dragging an extension-plane feature into a check
// every implementation has to perform. Resolving to a key needs none of that: it is one rule,
// and a reader that has never heard of aliases applies it correctly.
//
// resolve maps an address to its X25519 public key, returning false when it cannot. Addresses
// that do not resolve are skipped rather than treated as a mismatch — a directory miss is not
// evidence of misaddressing. Callers should answer their own address from local state so the
// common case costs no lookup at all.
//
// WHERE IT MUST NOT BE CALLED. Not inside DecryptHeader, and not by a bridge. A browser seals
// its outbound-to-legacy copy with recipient_address set to the LEGACY recipient while wrapping
// the CEK to the bridge's key, so the bridge's own mailbox key is deliberately absent from the
// audience.
//
// HONEST LIMIT: this trades a local comparison for a directory answer, so a fleet willing to
// serve a record binding the original recipient's address to the reader's key can defeat it.
// A fleet that hostile can already do worse, and counterparty pinning covers known contacts —
// but it is a weaker footing than a purely local check.
func (h *MessageHeader) AddressedToKey(mailboxKey [32]byte, resolve func(string) ([32]byte, bool)) bool {
	if mailboxKey == ([32]byte{}) || resolve == nil {
		return false
	}
	for _, addr := range h.Audience() {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if key, ok := resolve(addr); ok && key == mailboxKey {
			return true
		}
	}
	return false
}

// MessageContent is the large part of a message: body + attachments.
type MessageContent struct {
	Body        MessageBody
	Attachments []AttachmentRecord
	// Alternatives are richer renderings of Body (see PlaintextMessage.Alternatives).
	// Covered by MessageHeader.BodyHash and the body content address exactly like Body,
	// so a text/html part cannot be swapped without breaking the header signature.
	Alternatives []MessageBody
}

func (h *MessageHeader) toProto() *dmcnpb.MessageHeader {
	return &dmcnpb.MessageHeader{
		Version:            h.Version,
		MessageId:          h.MessageID[:],
		ThreadId:           h.ThreadID[:],
		SenderAddress:      h.SenderAddress,
		SenderPublicKey:    h.SenderPublicKey,
		RecipientAddress:   h.RecipientAddress,
		SentAt:             h.SentAt.Unix(),
		Subject:            h.Subject,
		AttachmentCount:    h.AttachmentCount,
		BodySize:           h.BodySize,
		Snippet:            h.Snippet,
		ReplyToId:          h.ReplyToID[:],
		BodyHash:           h.BodyHash[:],
		BodyContentAddress: h.BodyContentAddress,
		To:                 h.To,
		Cc:                 h.Cc,
		Bcc:                h.Bcc,
		SenderDisplay:      h.SenderDisplay,
	}
}

func messageHeaderFromProto(pb *dmcnpb.MessageHeader) MessageHeader {
	h := MessageHeader{
		Version:          pb.Version,
		SenderAddress:    pb.SenderAddress,
		SenderPublicKey:  pb.SenderPublicKey,
		RecipientAddress: pb.RecipientAddress,
		SentAt:           time.Unix(pb.SentAt, 0).UTC(),
		Subject:          pb.Subject,
		AttachmentCount:  pb.AttachmentCount,
		BodySize:         pb.BodySize,
		Snippet:          pb.Snippet,
	}
	copy(h.MessageID[:], pb.MessageId)
	copy(h.ThreadID[:], pb.ThreadId)
	copy(h.ReplyToID[:], pb.ReplyToId)
	copy(h.BodyHash[:], pb.BodyHash)
	h.BodyContentAddress = pb.BodyContentAddress
	h.To = pb.To
	h.Cc = pb.Cc
	h.Bcc = pb.Bcc
	// Deliberately NOT sanitized here: this is the parse path, and the signature is
	// verified by re-marshaling what we parsed. Normalizing on the way in would change
	// those bytes and reject every header whose producer wrote something this version
	// would clean up. Sanitizing belongs at the producer (SanitizeDisplayName, applied
	// by Split) and at the reader's render step.
	h.SenderDisplay = pb.SenderDisplay
	return h
}

func (c *MessageContent) toProto() *dmcnpb.MessageContent {
	pb := &dmcnpb.MessageContent{
		Body: &dmcnpb.MessageBody{
			ContentType: c.Body.ContentType,
			Content:     c.Body.Content,
		},
		Alternatives: bodiesToProto(c.Alternatives),
	}
	for _, a := range c.Attachments {
		pb.Attachments = append(pb.Attachments, attachmentToProto(a))
	}
	return pb
}

func messageContentFromProto(pb *dmcnpb.MessageContent) MessageContent {
	c := MessageContent{
		Body: MessageBody{
			ContentType: pb.GetBody().GetContentType(),
			Content:     pb.GetBody().GetContent(),
		},
		Alternatives: bodiesFromProto(pb.Alternatives),
	}
	for _, a := range pb.Attachments {
		c.Attachments = append(c.Attachments, attachmentFromProto(a))
	}
	return c
}

// hash returns SHA-256 over the canonical serialization of the content, used as
// the header's body commitment.
func (c *MessageContent) hash() ([32]byte, error) {
	data, err := protoMarshal(c.toProto())
	if err != nil {
		return [32]byte{}, fmt.Errorf("message: hash content: %w", err)
	}
	return crypto.SHA256Hash(data), nil
}

// headerSignableBytes is ctxMsgHeader || canonical(MessageHeader).
func (sh *SignedHeader) headerSignableBytes() ([]byte, error) {
	data, err := protoMarshal(sh.Header.toProto())
	if err != nil {
		return nil, fmt.Errorf("message: marshal header: %w", err)
	}
	return append([]byte(ctxMsgHeader), data...), nil
}

// Sign sets SenderSignature over the canonical, context-separated header.
func (sh *SignedHeader) Sign(senderPriv ed25519.PrivateKey) error {
	data, err := sh.headerSignableBytes()
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(senderPriv, data)
	if err != nil {
		return fmt.Errorf("message: sign header: %w", err)
	}
	copy(sh.SenderSignature[:], sig)
	return nil
}

// Verify validates the header signature against the header's sender public key.
func (sh *SignedHeader) Verify() error {
	data, err := sh.headerSignableBytes()
	if err != nil {
		return err
	}
	if err := crypto.Verify(sh.Header.SenderPublicKey, data, sh.SenderSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// Split derives a signed header + content from a composed PlaintextMessage: it
// computes the body hash, fills the preview fields, and signs the header.
func Split(msg *PlaintextMessage, senderPriv ed25519.PrivateKey) (*SignedHeader, *MessageContent, error) {
	content := &MessageContent{Body: msg.Body, Attachments: msg.Attachments, Alternatives: msg.Alternatives}
	bodyHash, err := content.hash()
	if err != nil {
		return nil, nil, err
	}

	sh := &SignedHeader{Header: MessageHeader{
		Version:          msg.Version,
		MessageID:        msg.MessageID,
		ThreadID:         msg.ThreadID,
		SenderAddress:    msg.SenderAddress,
		SenderPublicKey:  msg.SenderPublicKey,
		RecipientAddress: msg.RecipientAddress,
		SentAt:           msg.SentAt,
		Subject:          msg.Subject,
		AttachmentCount:  uint32(len(msg.Attachments)),
		BodySize:         uint64(len(msg.Body.Content)),
		Snippet:          snippetOf(msg.Body),
		ReplyToID:        msg.ReplyToID,
		BodyHash:         bodyHash,
		SenderDisplay:    SanitizeDisplayName(msg.SenderDisplay),
	}}
	if err := sh.Sign(senderPriv); err != nil {
		return nil, nil, err
	}
	return sh, content, nil
}

// VerifySnippet reports whether a header's snippet is what its body actually begins with.
//
// Both are signed by the same key, but only the BODY is bound to the header (body_hash, and
// the body's content address). The snippet is not, so a signer can seal a header whose
// snippet disagrees with its own body — and a reader listing an inbox, which never fetches
// bodies, has nothing to compare against. That is the point of checking here: this is the one
// moment the truth is available.
//
// A false result is not corruption and not a relay's doing; a relay cannot alter either half
// without breaking the header signature. It means the signer wrote one thing in the preview
// and another in the message, deliberately. Callers should surface that rather than refuse
// the message: the body is authentic, and hiding real mail over a misleading preview is the
// worse failure.
func VerifySnippet(h *MessageHeader, content *MessageContent) bool {
	if h == nil || content == nil {
		return false
	}
	return h.Snippet == snippetOf(content.Body)
}

// snippetOf produces the header's snippet: the leading bytes of a text body, as the longest
// valid-UTF-8 prefix of the first snippetMax bytes (never splitting a multibyte rune, so the
// signed header round-trips identically across implementations).
//
// The prefix IS the contract (SPEC.md): a producer must derive this from the body it is
// sealing. Nothing binds the two the way body_hash binds the body, so a reader that has the
// body should re-derive and compare — see VerifySnippet.
func snippetOf(body MessageBody) string {
	if body.ContentType != "text/plain" {
		return ""
	}
	s := body.Content
	if len(s) > snippetMax {
		s = s[:snippetMax]
	}
	// Drop a trailing incomplete rune.
	for len(s) > 0 && !utf8.Valid(s) {
		s = s[:len(s)-1]
	}
	return string(s)
}

// EncryptSplit seals a signed header and content into a split EncryptedEnvelope,
// using one per-message CEK wrapped for each recipient (same KEM as Encrypt).
//
// The body is encrypted first so its ciphertext can be content-addressed
// (CIDv1 of body_nonce||encrypted_body||body_tag); that address is written into
// the header and the header is (re)signed with senderPriv before being encrypted,
// so the sender signature commits to the exact ciphertext blob. The same address
// is also carried in the clear on the envelope for keyless relay verification.
func EncryptSplit(sh *SignedHeader, content *MessageContent, recipients []RecipientInfo, senderPriv ed25519.PrivateKey) (*EncryptedEnvelope, error) {
	if len(recipients) == 0 {
		return nil, errors.New("message: encrypt split: at least one recipient required")
	}

	bodyBytes, err := protoMarshal(content.toProto())
	if err != nil {
		return nil, fmt.Errorf("message: encrypt split: marshal content: %w", err)
	}

	cek, err := crypto.RandomBytes(crypto.AES256KeySize)
	if err != nil {
		return nil, fmt.Errorf("message: encrypt split: CEK: %w", err)
	}

	// Work on a copy. Below, this function stamps BodyContentAddress into the header and
	// re-signs it, so sealing one SignedHeader twice would silently give the second copy a
	// header committing to the FIRST copy's body. Every caller today does one Split per
	// EncryptSplit, which is the only reason mutating in place was safe. A shallow copy is
	// enough: the fields mutated here are a slice header and a fixed-size array, so the
	// caller's Header slices are never written through.
	shCopy := *sh
	sh = &shCopy

	// Body first: it is the content-addressed unit.
	bClass := selectSizeClass(uint32(len(bodyBytes)))
	bNonce, bCT, bTag, err := crypto.AESGCMEncryptAAD(cek, padPayload(bodyBytes, bClass), bodyAAD(producerKDF))
	if err != nil {
		return nil, fmt.Errorf("message: encrypt split: body: %w", err)
	}

	addr, err := ComputeBodyContentAddress(bNonce, bCT, bTag)
	if err != nil {
		return nil, fmt.Errorf("message: encrypt split: content address: %w", err)
	}

	// Commit to the ciphertext address in the header and (re)sign — the address did
	// not exist when Split() signed the header, so this signature is the authoritative
	// one. (The earlier Split() signature is intentionally overwritten.)
	sh.Header.BodyContentAddress = addr
	if err := sh.Sign(senderPriv); err != nil {
		return nil, fmt.Errorf("message: encrypt split: re-sign header: %w", err)
	}

	headerBytes, err := protoMarshal(&dmcnpb.SignedHeader{
		Header:          sh.Header.toProto(),
		SenderSignature: sh.SenderSignature[:],
	})
	if err != nil {
		return nil, fmt.Errorf("message: encrypt split: marshal header: %w", err)
	}
	hClass := selectSizeClass(uint32(len(headerBytes)))
	hNonce, hCT, hTag, err := crypto.AESGCMEncryptAAD(cek, padPayload(headerBytes, hClass), headerAAD(producerKDF))
	if err != nil {
		return nil, fmt.Errorf("message: encrypt split: header: %w", err)
	}

	recs := make([]RecipientRecord, len(recipients))
	for i, r := range recipients {
		rec, err := wrapCEK(cek, r)
		if err != nil {
			return nil, fmt.Errorf("message: encrypt split: wrap CEK %d: %w", i, err)
		}
		recs[i] = rec
	}

	env := &EncryptedEnvelope{
		Version:            2,
		MessageID:          sh.Header.MessageID,
		Recipients:         recs,
		CreatedAt:          sh.Header.SentAt.Unix(),
		EncryptedHeader:    hCT,
		HeaderSizeClass:    hClass,
		EncryptedBody:      bCT,
		BodySizeClass:      bClass,
		BodyContentAddress: addr,
	}
	copy(env.HeaderNonce[:], hNonce)
	copy(env.HeaderTag[:], hTag)
	copy(env.BodyNonce[:], bNonce)
	copy(env.BodyTag[:], bTag)
	return env, nil
}

// unwrapFor returns the CEK and the derivation generation the matching record declared. The
// caller needs the second value: the blobs' AEAD data is keyed on the same generation, so it
// comes from the record rather than from a guess.
func (e *EncryptedEnvelope) unwrapFor(recipientPriv, recipientPub [32]byte) ([]byte, uint32, error) {
	for i := range e.Recipients {
		if e.Recipients[i].RecipientXPub == recipientPub {
			cek, err := unwrapCEK(&e.Recipients[i], recipientPriv, recipientPub)
			if err != nil {
				return nil, 0, err
			}
			return cek, normalizeKDF(e.Recipients[i].KDF), nil
		}
	}
	return nil, 0, ErrRecipientNotFound
}

// DecryptHeader unwraps the CEK, decrypts the header, and verifies its signature.
// The returned header is safe to render as an inbox preview (its signature commits
// to the body via BodyHash).
func DecryptHeader(env *EncryptedEnvelope, recipientPriv, recipientPub [32]byte) (*SignedHeader, error) {
	if !env.IsSplit() {
		return nil, errors.New("message: envelope is not split (no header)")
	}
	cek, kdf, err := env.unwrapFor(recipientPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	padded, err := crypto.AESGCMDecryptAAD(cek, env.HeaderNonce[:], env.EncryptedHeader, env.HeaderTag[:], headerAAD(kdf))
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrDecryptionFailed, err)
	}
	unpadded, err := unpadPayload(padded)
	if err != nil {
		return nil, err
	}
	pb := &dmcnpb.SignedHeader{}
	if err := proto.Unmarshal(unpadded, pb); err != nil {
		return nil, fmt.Errorf("%w: header unmarshal: %v", ErrDecryptionFailed, err)
	}
	sh := &SignedHeader{Header: messageHeaderFromProto(pb.GetHeader())}
	copy(sh.SenderSignature[:], pb.GetSenderSignature())
	if err := sh.Verify(); err != nil {
		return nil, err
	}
	return sh, nil
}

// DecryptBody decrypts the body and verifies it against the (already-verified)
// header's BodyHash. Pass the header returned by DecryptHeader.
func DecryptBody(env *EncryptedEnvelope, header *MessageHeader, recipientPriv, recipientPub [32]byte) (*MessageContent, error) {
	if !env.IsSplit() {
		return nil, errors.New("message: envelope is not split (no body)")
	}
	cek, kdf, err := env.unwrapFor(recipientPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	padded, err := crypto.AESGCMDecryptAAD(cek, env.BodyNonce[:], env.EncryptedBody, env.BodyTag[:], bodyAAD(kdf))
	if err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrDecryptionFailed, err)
	}
	unpadded, err := unpadPayload(padded)
	if err != nil {
		return nil, err
	}
	pb := &dmcnpb.MessageContent{}
	if err := proto.Unmarshal(unpadded, pb); err != nil {
		return nil, fmt.Errorf("%w: body unmarshal: %v", ErrDecryptionFailed, err)
	}
	content := messageContentFromProto(pb)
	got, err := content.hash()
	if err != nil {
		return nil, err
	}
	if got != header.BodyHash {
		return nil, ErrBodyHashMismatch
	}
	// Content-address binding: the (already signature-verified) header commits to
	// the exact ciphertext blob. Recompute the address from the envelope's body
	// bytes and require it to match. Skipped when the header predates the feature
	// (empty address), where body_hash above is the sole commitment.
	if len(header.BodyContentAddress) > 0 {
		ok, err := env.bodyAddressMatches(header.BodyContentAddress)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrBodyAddressMismatch
		}
	}
	return &content, nil
}
