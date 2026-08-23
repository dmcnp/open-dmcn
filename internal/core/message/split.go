package message

import (
	"crypto/ed25519"
	"errors"
	"fmt"
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
}

// SignedHeader wraps a MessageHeader with the sender's signature (which covers
// BodyHash, so a verified header also authenticates the eventual body).
type SignedHeader struct {
	Header          MessageHeader
	SenderSignature [64]byte
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
	}}
	if err := sh.Sign(senderPriv); err != nil {
		return nil, nil, err
	}
	return sh, content, nil
}

// snippetOf returns a short preview of a text body (empty for non-text). The
// result is always the longest valid-UTF-8 prefix of the first snippetMax bytes,
// so the signed header round-trips identically across implementations (a Go
// byte-slice could otherwise split a multibyte rune and a protobufjs verifier
// would re-encode it differently, breaking the signature).
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

	// Body first: it is the content-addressed unit.
	bClass := selectSizeClass(uint32(len(bodyBytes)))
	bNonce, bCT, bTag, err := crypto.AESGCMEncrypt(cek, padPayload(bodyBytes, bClass))
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
	hNonce, hCT, hTag, err := crypto.AESGCMEncrypt(cek, padPayload(headerBytes, hClass))
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

// unwrapFor finds the recipient's wrapped CEK in the envelope and unwraps it.
func (e *EncryptedEnvelope) unwrapFor(recipientPriv, recipientPub [32]byte) ([]byte, error) {
	for i := range e.Recipients {
		if e.Recipients[i].RecipientXPub == recipientPub {
			return unwrapCEK(&e.Recipients[i], recipientPriv)
		}
	}
	return nil, ErrRecipientNotFound
}

// DecryptHeader unwraps the CEK, decrypts the header, and verifies its signature.
// The returned header is safe to render as an inbox preview (its signature commits
// to the body via BodyHash).
func DecryptHeader(env *EncryptedEnvelope, recipientPriv, recipientPub [32]byte) (*SignedHeader, error) {
	if !env.IsSplit() {
		return nil, errors.New("message: envelope is not split (no header)")
	}
	cek, err := env.unwrapFor(recipientPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	padded, err := crypto.AESGCMDecrypt(cek, env.HeaderNonce[:], env.EncryptedHeader, env.HeaderTag[:])
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrDecryptionFailed, err)
	}
	pb := &dmcnpb.SignedHeader{}
	if err := proto.Unmarshal(unpadPayload(padded), pb); err != nil {
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
	cek, err := env.unwrapFor(recipientPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	padded, err := crypto.AESGCMDecrypt(cek, env.BodyNonce[:], env.EncryptedBody, env.BodyTag[:])
	if err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrDecryptionFailed, err)
	}
	pb := &dmcnpb.MessageContent{}
	if err := proto.Unmarshal(unpadPayload(padded), pb); err != nil {
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
