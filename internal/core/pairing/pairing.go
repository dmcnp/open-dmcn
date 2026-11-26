// Package pairing implements device pairing (SPEC_EXT_DEVICES.md §8): bringing an account onto
// a new device with no file to move.
//
// The newcomer generates a throwaway identity at pairing.local, publishes its self-signed
// record so its mailbox can be found, and sends a CloneRequest to the account. A device already
// on the account shows the request, the person types in the confirmation code the newcomer
// shows, and the approver enrols the newcomer's device key and sends back a CloneResponse: the
// account's keys, sealed to the throwaway key, in a message signed by the account key.
//
// Both payloads ride as attachments with their own content types. A reader parses them and
// never re-encodes them to check a signature, so only the confirmation code, a hash over raw
// key bytes, has to match between implementations byte for byte.
package pairing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"google.golang.org/protobuf/proto"
)

const (
	// CloneRequestContentType marks the attachment carrying a CloneRequest.
	CloneRequestContentType = "application/x-dmcn-clone-request"
	// CloneRequestReadContentType marks a request to read and organise the mailbox and never to
	// send from it. A type of its own, so an approver that predates it finds no pairing request
	// in the message and cannot answer with the signing key by mistake.
	CloneRequestReadContentType = "application/x-dmcn-clone-request-read"
	// CloneResponseContentType marks the attachment carrying a CloneResponse.
	CloneResponseContentType = "application/x-dmcn-clone-response"

	// SubjectRequest / SubjectApproval are sentinel subjects so clients can
	// pre-filter pairing control messages from a mailbox LIST (the preview)
	// without decrypting every body, and hide them from the normal inbox.
	SubjectRequest  = "[DMCN] Device pairing request"
	SubjectApproval = "[DMCN] Device pairing approval"

	// EphemeralDomain is the domain used for throwaway ephemeral pairing
	// addresses. They are never real, registered, or routable as email.
	EphemeralDomain = "pairing.local"

	// EphemeralTTL is how long the ephemeral identity record stays valid. It is
	// single-use; this just bounds how long an abandoned record lingers.
	EphemeralTTL = 15 * time.Minute

	// sasContext domain-separates the confirmation-code hash.
	sasContext = "dmcn-pair-sas-v1\x00"
)

// CloneRequestData is the decoded payload of a clone-request attachment.
type CloneRequestData struct {
	EphemeralEd25519Pub ed25519.PublicKey
	EphemeralX25519Pub  [32]byte
	DeviceID            [16]byte
	Label               string
	RequestedAt         time.Time
	// DeviceEd25519Pub is the new device's own signing key, for the approver to enrol. Empty
	// from a client that predates the device registry.
	DeviceEd25519Pub ed25519.PublicKey
	// ReadOnly reports that the request arrived under CloneRequestReadContentType. It is not
	// part of the payload: the attachment type carries it.
	ReadOnly bool
}

// CloneResponseData is the decoded payload of a clone-response attachment: the
// account identity's full key material.
type CloneResponseData struct {
	Address        string
	Ed25519Public  ed25519.PublicKey
	Ed25519Private ed25519.PrivateKey
	X25519Public   [32]byte
	X25519Private  [32]byte
	DeviceID       [16]byte
	CreatedAt      time.Time
}

// KeyPair reconstructs an IdentityKeyPair from a decoded clone response.
func (d *CloneResponseData) KeyPair() *identity.IdentityKeyPair {
	return &identity.IdentityKeyPair{
		Ed25519Public:  d.Ed25519Public,
		Ed25519Private: d.Ed25519Private,
		X25519Public:   d.X25519Public,
		X25519Private:  d.X25519Private,
		CreatedAt:      d.CreatedAt,
		DeviceID:       d.DeviceID,
	}
}

// ConfirmationCode derives the short authentication string both devices display
// for out-of-band comparison. It binds the account address and the exact
// ephemeral keys the origin will encrypt the response to, so a matching code
// guarantees approval targets the genuine requesting device.
//
// Format: three groups of four decimal digits, e.g. "0428-9173-5560".
func ConfirmationCode(accountAddress string, ephEd25519Pub, ephX25519Pub []byte) string {
	h := sha256.New()
	h.Write([]byte(sasContext))
	h.Write([]byte(accountAddress))
	h.Write(ephEd25519Pub)
	h.Write(ephX25519Pub)
	sum := h.Sum(nil)

	// First 6 bytes (48 bits, < 2^53 so JS can mirror this exactly) → 12 digits.
	var n uint64
	for i := 0; i < 6; i++ {
		n = n<<8 | uint64(sum[i])
	}
	n %= 1_000_000_000_000
	s := fmt.Sprintf("%012d", n)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}

// IsEphemeralAddress reports whether addr is a throwaway device-pairing address
// on the reserved EphemeralDomain. These addresses are never real, registered, or
// routable as email, so callers may treat their records as powerless throwaways
// (a relay accepts one with no domain record behind it).
func IsEphemeralAddress(addr string) bool {
	return strings.HasSuffix(addr, "@"+EphemeralDomain)
}

// EphemeralAddress returns a fresh, unique throwaway address for an ephemeral
// pairing identity.
func EphemeralAddress() (string, error) {
	b, err := crypto.RandomBytes(8)
	if err != nil {
		return "", fmt.Errorf("pairing: ephemeral address: %w", err)
	}
	return "pair-" + hex.EncodeToString(b) + "@" + EphemeralDomain, nil
}

// NewEphemeralRecord builds a self-signed, tier-0 IdentityRecord for an ephemeral
// pairing identity, with the given relay as its only hint and a short expiry. The
// record is signed and ready to register.
func NewEphemeralRecord(address string, kp *identity.IdentityKeyPair, relayHint string, now time.Time) (*identity.IdentityRecord, error) {
	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		return nil, fmt.Errorf("pairing: ephemeral record: %w", err)
	}
	rec.RelayHints = []string{relayHint}
	rec.ExpiresAt = now.Add(EphemeralTTL).UTC()
	if err := rec.Sign(kp); err != nil {
		return nil, fmt.Errorf("pairing: sign ephemeral record: %w", err)
	}
	return rec, nil
}

// MarshalCloneRequest serializes a clone-request payload.
func MarshalCloneRequest(d *CloneRequestData) ([]byte, error) {
	pb := &dmcnpb.CloneRequest{
		EphemeralEd25519Pub: d.EphemeralEd25519Pub,
		EphemeralX25519Pub:  d.EphemeralX25519Pub[:],
		DeviceId:            d.DeviceID[:],
		Label:               d.Label,
		RequestedAt:         d.RequestedAt.Unix(),
		DeviceEd25519Pub:    d.DeviceEd25519Pub,
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(pb)
}

// MarshalCloneResponse serializes a clone-response payload (the key bundle).
func MarshalCloneResponse(d *CloneResponseData) ([]byte, error) {
	pb := &dmcnpb.CloneResponse{
		Address:        d.Address,
		Ed25519Public:  d.Ed25519Public,
		Ed25519Private: d.Ed25519Private,
		X25519Public:   d.X25519Public[:],
		X25519Private:  d.X25519Private[:],
		DeviceId:       d.DeviceID[:],
		CreatedAt:      d.CreatedAt.Unix(),
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(pb)
}

func unmarshalCloneRequest(data []byte) (*CloneRequestData, error) {
	pb := &dmcnpb.CloneRequest{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("pairing: unmarshal clone request: %w", err)
	}
	d := &CloneRequestData{
		EphemeralEd25519Pub: pb.EphemeralEd25519Pub,
		Label:               pb.Label,
		RequestedAt:         time.Unix(pb.RequestedAt, 0).UTC(),
		DeviceEd25519Pub:    pb.DeviceEd25519Pub,
	}
	copy(d.EphemeralX25519Pub[:], pb.EphemeralX25519Pub)
	copy(d.DeviceID[:], pb.DeviceId)
	return d, nil
}

func unmarshalCloneResponse(data []byte) (*CloneResponseData, error) {
	pb := &dmcnpb.CloneResponse{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("pairing: unmarshal clone response: %w", err)
	}
	d := &CloneResponseData{
		Address:        pb.Address,
		Ed25519Public:  pb.Ed25519Public,
		Ed25519Private: pb.Ed25519Private,
		CreatedAt:      time.Unix(pb.CreatedAt, 0).UTC(),
	}
	copy(d.X25519Public[:], pb.X25519Public)
	copy(d.X25519Private[:], pb.X25519Private)
	copy(d.DeviceID[:], pb.DeviceId)
	return d, nil
}

// attachmentFor wraps marshaled control bytes in an AttachmentRecord.
func attachmentFor(contentType, filename string, content []byte) (message.AttachmentRecord, error) {
	attID, err := crypto.RandomUUID()
	if err != nil {
		return message.AttachmentRecord{}, fmt.Errorf("pairing: attachment id: %w", err)
	}
	return message.AttachmentRecord{
		AttachmentID: attID,
		Filename:     filename,
		ContentType:  contentType,
		SizeBytes:    uint64(len(content)),
		ContentHash:  crypto.SHA256Hash(content),
		Content:      content,
	}, nil
}

// BuildCloneRequestMessage composes the clone-request message sent from the
// ephemeral identity into the account mailbox.
func BuildCloneRequestMessage(eph *identity.IdentityKeyPair, ephAddress, accountAddress, label string) (*message.PlaintextMessage, error) {
	d := &CloneRequestData{
		EphemeralEd25519Pub: eph.Ed25519Public,
		EphemeralX25519Pub:  eph.X25519Public,
		DeviceID:            eph.DeviceID,
		Label:               label,
		RequestedAt:         time.Now().UTC(),
	}
	body, err := MarshalCloneRequest(d)
	if err != nil {
		return nil, err
	}
	msg, err := message.NewPlaintextMessage(ephAddress, accountAddress, SubjectRequest,
		"A new device is requesting access to this identity. Approve it from a device you already trust.",
		eph.Ed25519Public)
	if err != nil {
		return nil, fmt.Errorf("pairing: compose request: %w", err)
	}
	att, err := attachmentFor(CloneRequestContentType, "clone-request.bin", body)
	if err != nil {
		return nil, err
	}
	msg.Attachments = append(msg.Attachments, att)
	return msg, nil
}

// BuildCloneResponseMessage composes the clone-response message sent from the
// account identity into the ephemeral mailbox, carrying the account key bundle.
func BuildCloneResponseMessage(account *identity.IdentityKeyPair, accountAddress, ephAddress string) (*message.PlaintextMessage, error) {
	d := &CloneResponseData{
		Address:        accountAddress,
		Ed25519Public:  account.Ed25519Public,
		Ed25519Private: account.Ed25519Private,
		X25519Public:   account.X25519Public,
		X25519Private:  account.X25519Private,
		DeviceID:       account.DeviceID,
		CreatedAt:      account.CreatedAt,
	}
	body, err := MarshalCloneResponse(d)
	if err != nil {
		return nil, err
	}
	msg, err := message.NewPlaintextMessage(accountAddress, ephAddress, SubjectApproval,
		"Device pairing approved.", account.Ed25519Public)
	if err != nil {
		return nil, fmt.Errorf("pairing: compose response: %w", err)
	}
	att, err := attachmentFor(CloneResponseContentType, "clone-response.bin", body)
	if err != nil {
		return nil, err
	}
	msg.Attachments = append(msg.Attachments, att)
	return msg, nil
}

// ExtractCloneRequest returns the decoded clone-request from a message's content,
// or (nil, false) if no clone-request attachment is present.
func ExtractCloneRequest(content *message.MessageContent) (*CloneRequestData, bool) {
	for i := range content.Attachments {
		ct := content.Attachments[i].ContentType
		if ct == CloneRequestContentType || ct == CloneRequestReadContentType {
			d, err := unmarshalCloneRequest(content.Attachments[i].Content)
			if err != nil {
				return nil, false
			}
			d.ReadOnly = ct == CloneRequestReadContentType
			return d, true
		}
	}
	return nil, false
}

// ExtractCloneResponse returns the decoded clone-response from a message's
// content, or (nil, false) if no clone-response attachment is present.
func ExtractCloneResponse(content *message.MessageContent) (*CloneResponseData, bool) {
	for i := range content.Attachments {
		if content.Attachments[i].ContentType == CloneResponseContentType {
			d, err := unmarshalCloneResponse(content.Attachments[i].Content)
			if err != nil {
				return nil, false
			}
			return d, true
		}
	}
	return nil, false
}
