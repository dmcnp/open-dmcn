// Package message implements the three-layer message structure defined in
// whitepaper Section 15.3: PlaintextMessage, SignedMessage, and EncryptedEnvelope.
package message

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrInvalidSignature is returned when a message signature is invalid.
	ErrInvalidSignature = errors.New("message: invalid sender signature")
)

// protoMarshal is the protobuf marshaling function, overridable for testing.
var protoMarshal = func(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

// MessageBody holds the content of a message.
// See whitepaper Section 15.3.1.
type MessageBody struct {
	ContentType string // MIME type, e.g. "text/plain"
	Content     []byte // UTF-8 encoded body text
}

// AttachmentRecord describes an attachment within a message.
// See whitepaper Section 15.3.1.
type AttachmentRecord struct {
	AttachmentID [16]byte // random UUID
	Filename     string
	ContentType  string // MIME type
	SizeBytes    uint64
	ContentHash  [32]byte // SHA-256 of plaintext content
	Content      []byte
	// ContentID is the bare MIME Content-ID (no angle brackets) of an inline part the
	// HTML body references as <img src="cid:...">. Empty for an ordinary attachment.
	ContentID string
	// Disposition is "inline" or "attachment"; empty means attachment. An inline part
	// with a ContentID renders in place instead of showing up as a paperclip.
	Disposition string
}

// PlaintextMessage represents a composed message before signing or encryption.
// See whitepaper Section 15.3.1.
type PlaintextMessage struct {
	Version          uint32
	MessageID        [16]byte // random UUID
	ThreadID         [16]byte // UUID linking conversation thread
	SenderAddress    string
	SenderPublicKey  ed25519.PublicKey
	RecipientAddress string
	SentAt           time.Time
	Subject          string
	Body             MessageBody
	Attachments      []AttachmentRecord
	ReplyToID        [16]byte // zero = not a reply
	// Alternatives are richer renderings of Body — the multipart/alternative analog.
	// Body stays the primary text/plain fallback that every reader can display; a
	// text/html part rides here. A reader picks the richest form it can render safely.
	Alternatives []MessageBody
}

// NewPlaintextMessage creates a new PlaintextMessage with generated IDs.
func NewPlaintextMessage(from, to, subject, body string, senderPubKey ed25519.PublicKey) (*PlaintextMessage, error) {
	msgID, err := crypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("message: generate message ID: %w", err)
	}

	threadID, err := crypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("message: generate thread ID: %w", err)
	}

	return &PlaintextMessage{
		Version:          1,
		MessageID:        msgID,
		ThreadID:         threadID,
		SenderAddress:    from,
		SenderPublicKey:  senderPubKey,
		RecipientAddress: to,
		SentAt:           time.Now().UTC(),
		Subject:          subject,
		Body: MessageBody{
			ContentType: "text/plain",
			Content:     []byte(body),
		},
	}, nil
}

// attachmentToProto / attachmentFromProto and bodiesToProto / bodiesFromProto are shared
// by PlaintextMessage (here) and MessageContent (split.go) so the attachment and
// alternative-body mappings stay identical on both paths. They diverged once by simply
// not existing on one side, and the symptom was formatted mail silently arriving as
// plain text.
func attachmentToProto(a AttachmentRecord) *dmcnpb.AttachmentRecord {
	return &dmcnpb.AttachmentRecord{
		AttachmentId: a.AttachmentID[:],
		Filename:     a.Filename,
		ContentType:  a.ContentType,
		SizeBytes:    a.SizeBytes,
		ContentHash:  a.ContentHash[:],
		Content:      a.Content,
		ContentId:    a.ContentID,
		Disposition:  a.Disposition,
	}
}

func attachmentFromProto(a *dmcnpb.AttachmentRecord) AttachmentRecord {
	att := AttachmentRecord{
		Filename:    a.Filename,
		ContentType: a.ContentType,
		SizeBytes:   a.SizeBytes,
		Content:     a.Content,
		ContentID:   a.ContentId,
		Disposition: a.Disposition,
	}
	copy(att.AttachmentID[:], a.AttachmentId)
	copy(att.ContentHash[:], a.ContentHash)
	return att
}

func bodiesToProto(bodies []MessageBody) []*dmcnpb.MessageBody {
	if len(bodies) == 0 {
		return nil
	}
	out := make([]*dmcnpb.MessageBody, 0, len(bodies))
	for _, b := range bodies {
		out = append(out, &dmcnpb.MessageBody{ContentType: b.ContentType, Content: b.Content})
	}
	return out
}

func bodiesFromProto(pb []*dmcnpb.MessageBody) []MessageBody {
	if len(pb) == 0 {
		return nil
	}
	out := make([]MessageBody, 0, len(pb))
	for _, b := range pb {
		out = append(out, MessageBody{ContentType: b.GetContentType(), Content: b.GetContent()})
	}
	return out
}

// toProto converts PlaintextMessage to its protobuf representation.
func (m *PlaintextMessage) toProto() *dmcnpb.PlaintextMessage {
	pb := &dmcnpb.PlaintextMessage{
		Version:          m.Version,
		MessageId:        m.MessageID[:],
		ThreadId:         m.ThreadID[:],
		SenderAddress:    m.SenderAddress,
		SenderPublicKey:  m.SenderPublicKey,
		RecipientAddress: m.RecipientAddress,
		SentAt:           m.SentAt.Unix(),
		Subject:          m.Subject,
		Body: &dmcnpb.MessageBody{
			ContentType: m.Body.ContentType,
			Content:     m.Body.Content,
		},
		ReplyToId:    m.ReplyToID[:],
		Alternatives: bodiesToProto(m.Alternatives),
	}

	for _, a := range m.Attachments {
		pb.Attachments = append(pb.Attachments, attachmentToProto(a))
	}

	return pb
}

// plaintextMessageFromProto converts a protobuf PlaintextMessage back to the Go type.
func plaintextMessageFromProto(pb *dmcnpb.PlaintextMessage) *PlaintextMessage {
	m := &PlaintextMessage{
		Version:          pb.Version,
		SenderAddress:    pb.SenderAddress,
		SenderPublicKey:  pb.SenderPublicKey,
		RecipientAddress: pb.RecipientAddress,
		SentAt:           time.Unix(pb.SentAt, 0).UTC(),
		Subject:          pb.Subject,
		Body: MessageBody{
			ContentType: pb.Body.GetContentType(),
			Content:     pb.Body.GetContent(),
		},
		Alternatives: bodiesFromProto(pb.Alternatives),
	}

	copy(m.MessageID[:], pb.MessageId)
	copy(m.ThreadID[:], pb.ThreadId)
	copy(m.ReplyToID[:], pb.ReplyToId)

	for _, a := range pb.Attachments {
		m.Attachments = append(m.Attachments, attachmentFromProto(a))
	}

	return m
}

// SignedMessage wraps a PlaintextMessage with the sender's Ed25519 signature.
// See whitepaper Section 15.3.2.
type SignedMessage struct {
	Plaintext       PlaintextMessage
	SenderSignature [64]byte
}

// Sign computes and sets SenderSignature over the canonical protobuf
// serialization of the PlaintextMessage.
//
// See whitepaper Section 15.3.2.
func (sm *SignedMessage) Sign(senderPrivKey ed25519.PrivateKey) error {
	data, err := sm.signableBytes()
	if err != nil {
		return fmt.Errorf("message: sign: %w", err)
	}

	sig, err := crypto.Sign(senderPrivKey, data)
	if err != nil {
		return fmt.Errorf("message: sign: %w", err)
	}

	copy(sm.SenderSignature[:], sig)
	return nil
}

// Verify validates the SenderSignature against the sender's public key.
// Returns ErrInvalidSignature if the signature is not valid.
//
// A SignedMessage with an invalid signature must never be displayed to a user.
// See whitepaper Section 15.3.2.
func (sm *SignedMessage) Verify() error {
	data, err := sm.signableBytes()
	if err != nil {
		return fmt.Errorf("message: verify: %w", err)
	}

	if err := crypto.Verify(sm.Plaintext.SenderPublicKey, data, sm.SenderSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// signableBytes returns the canonical protobuf serialization of the PlaintextMessage.
func (sm *SignedMessage) signableBytes() ([]byte, error) {
	pb := sm.Plaintext.toProto()
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// toProto converts SignedMessage to its protobuf representation.
func (sm *SignedMessage) toProto() *dmcnpb.SignedMessage {
	return &dmcnpb.SignedMessage{
		Plaintext:       sm.Plaintext.toProto(),
		SenderSignature: sm.SenderSignature[:],
	}
}

// signedMessageFromProto converts a protobuf SignedMessage back to the Go type.
func signedMessageFromProto(pb *dmcnpb.SignedMessage) *SignedMessage {
	sm := &SignedMessage{
		Plaintext: *plaintextMessageFromProto(pb.Plaintext),
	}
	copy(sm.SenderSignature[:], pb.SenderSignature)
	return sm
}
