// Package message implements the three-layer message structure defined in
// SPEC.md §3: PlaintextMessage, SignedMessage, and EncryptedEnvelope.
package message

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
// See SPEC.md §3.
type MessageBody struct {
	ContentType string // MIME type, e.g. "text/plain"
	Content     []byte // UTF-8 encoded body text
}

// AttachmentRecord describes an attachment within a message.
// See SPEC.md §3.
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
// See SPEC.md §3.
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
	// SenderDisplay is an optional human-readable name for the sender, copied into
	// the signed header by Split. Display only — see MessageHeader.SenderDisplay.
	SenderDisplay string
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
		ReplyToId:     m.ReplyToID[:],
		Alternatives:  bodiesToProto(m.Alternatives),
		SenderDisplay: m.SenderDisplay,
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
		Alternatives:  bodiesFromProto(pb.Alternatives),
		SenderDisplay: pb.SenderDisplay,
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
// See SPEC.md §3.
type SignedMessage struct {
	Plaintext       PlaintextMessage
	SenderSignature [64]byte
}

// Sign computes and sets SenderSignature over the canonical protobuf
// serialization of the PlaintextMessage.
//
// See SPEC.md §3.
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
// See SPEC.md §3.
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

// maxDisplayNameLen caps a sender display name. Long enough for any real name or
// brand, short enough that it can't push the address out of a reader's view — which
// is the whole point of showing them together.
const maxDisplayNameLen = 96

// SanitizeDisplayName normalizes a sender display name for the wire. It runs at the
// PRODUCER (Split), never on the parse path: the header signature is verified by
// re-marshaling what was parsed, so cleaning a value on the way in would break the
// signature of every header that carried something we would now rewrite.
//
// Display names are the classic mail spoofing surface, and this one arrives from a
// legacy From header. So: drop control characters, drop the bidirectional-override
// codepoints that let "moc.live@rekcatta" render as a friendly name, collapse
// whitespace to single spaces, and cap the length. What survives is a single line of
// printable text that a reader can safely show NEXT TO the address.
func SanitizeDisplayName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r): // incl. tab/newline/NBSP: a name is one line
			space = b.Len() > 0
		case r == utf8.RuneError:
			// Invalid UTF-8: skip rather than emit a replacement glyph.
		case unicode.IsControl(r), isBidiControl(r):
			// Dropped, not replaced by a space: these are invisible, so replacing
			// them would let a name smuggle spacing a reader can't account for.
		default:
			if space {
				b.WriteByte(' ')
				space = false
			}
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > maxDisplayNameLen {
		out = out[:maxDisplayNameLen]
		for len(out) > 0 && !utf8.ValidString(out) { // never split a rune
			out = out[:len(out)-1]
		}
		out = strings.TrimRight(out, " ")
	}
	return out
}

// isBidiControl reports whether r is one of the Unicode bidirectional formatting
// codepoints. They reorder rendered text without being visible, which is exactly
// how a display name is made to read as something other than what it is.
func isBidiControl(r rune) bool {
	switch r {
	case 0x061C, // ARABIC LETTER MARK
		0x200E, 0x200F, // LEFT-TO-RIGHT / RIGHT-TO-LEFT MARK
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // EMBEDDING / OVERRIDE / POP
		0x2066, 0x2067, 0x2068, 0x2069: // ISOLATES
		return true
	}
	return false
}
