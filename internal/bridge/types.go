// Package bridge implements the SMTP-DMCN bridge protocol, allowing
// legacy email clients to exchange messages with DMCN users.
//
// See PRD Section 6 and whitepaper Section 15.6.
package bridge

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// protoMarshal is the protobuf marshaling function, overridable for testing.
var protoMarshal = func(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

var (
	// ErrInvalidSignature is returned when a bridge signature is invalid.
	ErrInvalidSignature = errors.New("bridge: invalid signature")
	// ErrRecipientNotFound is returned when the DMCN recipient cannot be found.
	ErrRecipientNotFound = errors.New("bridge: recipient not found in registry")
	// ErrSenderNotFound is returned when the DMCN sender cannot be found.
	ErrSenderNotFound = errors.New("bridge: sender not found in registry")
	// ErrNotLegacyAddress is returned when an outbound recipient is not a legacy address.
	ErrNotLegacyAddress = errors.New("bridge: recipient is not a legacy email address")
	// ErrMessageRejected is returned when an inbound message fails authentication
	// hard enough to be dropped (DMARC failure under a p=reject policy) rather
	// than delivered with a suspicious trust tier.
	ErrMessageRejected = errors.New("bridge: message rejected by authentication policy")
	// ErrSenderNotAuthorized is returned when an outbound message's DMCN sender
	// is not on a domain this bridge relays for (an open-relay guard). It is a
	// permanent rejection — the sender must use their own domain's bridge.
	ErrSenderNotAuthorized = errors.New("bridge: sender not authorized to relay through this bridge")
	// ErrOutboundRateLimited is returned when a sender exceeds the bridge's
	// per-sender outbound delivery rate limit. It is transient — the message may
	// succeed on a later poll once the window clears.
	ErrOutboundRateLimited = errors.New("bridge: outbound rate limit exceeded")
	// ErrMailLoop is returned when an inbound message has traversed too many MTAs
	// (excessive Received headers), indicating a forwarding loop. The message is
	// dropped rather than wrapped and delivered.
	ErrMailLoop = errors.New("bridge: mail loop detected")
	// ErrUnsafeHeader is returned when an outbound message's sender, recipient, or
	// subject contains CR/LF/NUL — a header-injection attempt — and is refused
	// before any SMTP message is built.
	ErrUnsafeHeader = errors.New("bridge: unsafe header content (possible injection)")
)

// BridgeTrustTier represents the trust classification assigned to an
// inbound legacy email message by the bridge node.
type BridgeTrustTier int

const (
	TrustTierUnspecified      BridgeTrustTier = 0
	TrustTierVerifiedLegacy   BridgeTrustTier = 1
	TrustTierUnverifiedLegacy BridgeTrustTier = 2
	TrustTierSuspicious       BridgeTrustTier = 3
)

// SPFResult represents the outcome of an SPF check.
type SPFResult int

const (
	SPFNone     SPFResult = 0
	SPFPass     SPFResult = 1
	SPFFail     SPFResult = 2
	SPFSoftFail SPFResult = 3
	SPFNeutral  SPFResult = 4
)

// DKIMResult represents the outcome of a DKIM check.
type DKIMResult int

const (
	DKIMNone DKIMResult = 0
	DKIMPass DKIMResult = 1
	DKIMFail DKIMResult = 2
)

// DMARCResult represents the outcome of a DMARC check.
type DMARCResult int

const (
	DMARCNone DMARCResult = 0
	DMARCPass DMARCResult = 1
	DMARCFail DMARCResult = 2
)

// DMARCPolicy is the published DMARC handling policy (the p= tag) of the
// From-header domain. It governs whether a DMARC failure is a hard reject:
// only p=reject failures are dropped (see ShouldReject); p=quarantine and
// p=none failures are delivered but classified as suspicious. It is bridge-
// internal — it is not carried in the signed classification record.
type DMARCPolicy int

const (
	DMARCPolicyNone       DMARCPolicy = 0 // no DMARC record, or p=none
	DMARCPolicyQuarantine DMARCPolicy = 1
	DMARCPolicyReject     DMARCPolicy = 2
)

// AuthResult holds the results of SPF, DKIM, and DMARC verification
// on an inbound email message.
type AuthResult struct {
	SPF         SPFResult
	DKIM        DKIMResult
	DMARC       DMARCResult
	DMARCPolicy DMARCPolicy
	SenderIP    string
}

// AuthVerifier checks SPF, DKIM, and DMARC on an inbound email.
type AuthVerifier interface {
	Verify(ctx context.Context, senderIP string, from string, data []byte) (*AuthResult, error)
}

// SMTPDeliverer sends an outbound SMTP message to a legacy email address. from/to are the
// SMTP envelope-aligned addresses (rewritten + injection-checked by the caller); msg carries the
// full content (subject, typed body, attachments, threading IDs) so the deliverer can render a
// faithful MIME message.
type SMTPDeliverer interface {
	Deliver(ctx context.Context, from, to string, msg *message.PlaintextMessage) error
}

// ClassificationContentType is the MIME type used for BridgeClassificationRecord
// attachments in DMCN messages.
const ClassificationContentType = "application/x-dmcn-bridge-classification"

// ReceiptContentType is the MIME type used for BridgeDeliveryReceipt
// attachments in DMCN messages.
const ReceiptContentType = "application/x-dmcn-bridge-delivery-receipt"

// BridgeClassificationRecord is a signed attestation by a bridge node
// describing the authentication outcome of an inbound legacy email.
type BridgeClassificationRecord struct {
	// BridgeAddress is the bridge's libp2p PEER ID, and is informational — for display and
	// logs. A bridge has no DMCN email address: it is infrastructure, not a correspondent, and
	// what makes its verdict trustworthy is BridgeCredential, not a directory entry.
	BridgeAddress   string
	BridgePublicKey ed25519.PublicKey // 32 bytes; == BridgeCredential.Subject
	SMTPFrom        string
	SMTPSenderIP    string
	SPFResult       SPFResult
	DKIMResult      DKIMResult
	DMARCResult     DMARCResult
	ReputationScore int32 // -100 to +100
	TrustTier       BridgeTrustTier
	ClassifiedAt    time.Time
	BridgeSignature [64]byte

	// BridgeCredential is the bridge's operator-signed credential (role "bridge"). Its subject
	// is BridgePublicKey, so a recipient verifies the credential against the domain's root key
	// and thereby confirms the signer really is a bridge that root authorised.
	//
	// Deliberately NOT covered by BridgeSignature: it carries its own signature from the root,
	// the subject==signer binding defeats any swap, and the whole record rides inside the
	// end-to-end-signed DMCN message that delivers it. Signing it too would only mean the
	// credential could not be re-issued without re-signing every historical attestation.
	BridgeCredential *identity.Credential
}

// Sign computes and sets BridgeSignature over all fields except the signature.
func (r *BridgeClassificationRecord) Sign(privKey ed25519.PrivateKey) error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("bridge: sign classification: %w", err)
	}

	sig, err := crypto.Sign(privKey, data)
	if err != nil {
		return fmt.Errorf("bridge: sign classification: %w", err)
	}

	copy(r.BridgeSignature[:], sig)
	return nil
}

// Verify validates BridgeSignature against the bridge's public key.
func (r *BridgeClassificationRecord) Verify() error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("bridge: verify classification: %w", err)
	}

	if err := crypto.Verify(r.BridgePublicKey, data, r.BridgeSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

func (r *BridgeClassificationRecord) signableBytes() ([]byte, error) {
	pb := &dmcnpb.BridgeClassificationRecord{
		BridgeAddress:   r.BridgeAddress,
		BridgePublicKey: r.BridgePublicKey,
		SmtpFrom:        r.SMTPFrom,
		SmtpSenderIp:    r.SMTPSenderIP,
		SpfResult:       dmcnpb.SPFResult(r.SPFResult),
		DkimResult:      dmcnpb.DKIMResult(r.DKIMResult),
		DmarcResult:     dmcnpb.DMARCResult(r.DMARCResult),
		ReputationScore: r.ReputationScore,
		TrustTier:       dmcnpb.BridgeTrustTier(r.TrustTier),
		ClassifiedAt:    r.ClassifiedAt.Unix(),
		// BridgeSignature intentionally omitted — this is what we sign over
	}

	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// ToProto converts the record to its protobuf representation.
func (r *BridgeClassificationRecord) ToProto() *dmcnpb.BridgeClassificationRecord {
	return &dmcnpb.BridgeClassificationRecord{
		BridgeAddress:    r.BridgeAddress,
		BridgePublicKey:  r.BridgePublicKey,
		SmtpFrom:         r.SMTPFrom,
		SmtpSenderIp:     r.SMTPSenderIP,
		SpfResult:        dmcnpb.SPFResult(r.SPFResult),
		DkimResult:       dmcnpb.DKIMResult(r.DKIMResult),
		DmarcResult:      dmcnpb.DMARCResult(r.DMARCResult),
		ReputationScore:  r.ReputationScore,
		TrustTier:        dmcnpb.BridgeTrustTier(r.TrustTier),
		ClassifiedAt:     r.ClassifiedAt.Unix(),
		BridgeSignature:  r.BridgeSignature[:],
		BridgeCredential: credToProto(r.BridgeCredential),
	}
}

// ClassificationRecordFromProto creates a BridgeClassificationRecord from
// its protobuf representation.
func ClassificationRecordFromProto(pb *dmcnpb.BridgeClassificationRecord) *BridgeClassificationRecord {
	r := &BridgeClassificationRecord{
		BridgeAddress:   pb.BridgeAddress,
		BridgePublicKey: pb.BridgePublicKey,
		SMTPFrom:        pb.SmtpFrom,
		SMTPSenderIP:    pb.SmtpSenderIp,
		SPFResult:       SPFResult(pb.SpfResult),
		DKIMResult:      DKIMResult(pb.DkimResult),
		DMARCResult:     DMARCResult(pb.DmarcResult),
		ReputationScore: pb.ReputationScore,
		TrustTier:       BridgeTrustTier(pb.TrustTier),
		ClassifiedAt:    time.Unix(pb.ClassifiedAt, 0).UTC(),
	}
	copy(r.BridgeSignature[:], pb.BridgeSignature)
	r.BridgeCredential = credFromProto(pb.BridgeCredential)
	return r
}

// Marshal serializes the classification record to protobuf bytes.
func (r *BridgeClassificationRecord) Marshal() ([]byte, error) {
	return protoMarshal(r.ToProto())
}

// UnmarshalClassificationRecord deserializes a BridgeClassificationRecord
// from protobuf bytes.
func UnmarshalClassificationRecord(data []byte) (*BridgeClassificationRecord, error) {
	pb := &dmcnpb.BridgeClassificationRecord{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("bridge: unmarshal classification: %w", err)
	}
	return ClassificationRecordFromProto(pb), nil
}

// BridgeDeliveryReceipt is a signed receipt from the bridge confirming
// outbound SMTP delivery of a DMCN message.
type BridgeDeliveryReceipt struct {
	OriginalMessageID [16]byte
	RecipientEmail    string
	// BridgeAddress is the bridge's libp2p PEER ID, informational — see
	// BridgeClassificationRecord.BridgeAddress.
	BridgeAddress   string
	DeliveredAt     time.Time
	Success         bool
	ErrorDetail     string
	BridgeSignature [64]byte

	// BridgeCredential lets the DMCN sender verify this receipt the same way a recipient
	// verifies a classification record. Subject == the signing key; not covered by
	// BridgeSignature, for the same reasons.
	BridgeCredential *identity.Credential
}

// Sign computes and sets BridgeSignature over all fields except the signature.
func (r *BridgeDeliveryReceipt) Sign(privKey ed25519.PrivateKey) error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("bridge: sign receipt: %w", err)
	}

	sig, err := crypto.Sign(privKey, data)
	if err != nil {
		return fmt.Errorf("bridge: sign receipt: %w", err)
	}

	copy(r.BridgeSignature[:], sig)
	return nil
}

// Verify validates BridgeSignature. The caller must provide the bridge's
// public key separately (e.g. from the registry).
func (r *BridgeDeliveryReceipt) Verify(pubKey ed25519.PublicKey) error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("bridge: verify receipt: %w", err)
	}

	if err := crypto.Verify(pubKey, data, r.BridgeSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

func (r *BridgeDeliveryReceipt) signableBytes() ([]byte, error) {
	pb := &dmcnpb.BridgeDeliveryReceipt{
		OriginalMessageId: r.OriginalMessageID[:],
		RecipientEmail:    r.RecipientEmail,
		BridgeAddress:     r.BridgeAddress,
		DeliveredAt:       r.DeliveredAt.Unix(),
		Success:           r.Success,
		ErrorDetail:       r.ErrorDetail,
		// BridgeSignature intentionally omitted
	}

	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// ToProto converts the receipt to its protobuf representation.
func (r *BridgeDeliveryReceipt) ToProto() *dmcnpb.BridgeDeliveryReceipt {
	return &dmcnpb.BridgeDeliveryReceipt{
		OriginalMessageId: r.OriginalMessageID[:],
		RecipientEmail:    r.RecipientEmail,
		BridgeAddress:     r.BridgeAddress,
		DeliveredAt:       r.DeliveredAt.Unix(),
		Success:           r.Success,
		ErrorDetail:       r.ErrorDetail,
		BridgeSignature:   r.BridgeSignature[:],
		BridgeCredential:  credToProto(r.BridgeCredential),
	}
}

// DeliveryReceiptFromProto creates a BridgeDeliveryReceipt from its
// protobuf representation.
func DeliveryReceiptFromProto(pb *dmcnpb.BridgeDeliveryReceipt) *BridgeDeliveryReceipt {
	r := &BridgeDeliveryReceipt{
		RecipientEmail: pb.RecipientEmail,
		BridgeAddress:  pb.BridgeAddress,
		DeliveredAt:    time.Unix(pb.DeliveredAt, 0).UTC(),
		Success:        pb.Success,
		ErrorDetail:    pb.ErrorDetail,
	}
	copy(r.OriginalMessageID[:], pb.OriginalMessageId)
	copy(r.BridgeSignature[:], pb.BridgeSignature)
	r.BridgeCredential = credFromProto(pb.BridgeCredential)
	return r
}

// Marshal serializes the delivery receipt to protobuf bytes.
func (r *BridgeDeliveryReceipt) Marshal() ([]byte, error) {
	return protoMarshal(r.ToProto())
}

// UnmarshalDeliveryReceipt deserializes a BridgeDeliveryReceipt from
// protobuf bytes.
func UnmarshalDeliveryReceipt(data []byte) (*BridgeDeliveryReceipt, error) {
	pb := &dmcnpb.BridgeDeliveryReceipt{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("bridge: unmarshal receipt: %w", err)
	}
	return DeliveryReceiptFromProto(pb), nil
}

// credToProto / credFromProto convert the attached bridge credential. A record with no
// credential round-trips as nil rather than erroring: verification rejects it (see
// VerifyClassificationAttestation), which is where that decision belongs — a parser that
// refuses to decode would deny a reader the chance to say WHY the attestation is untrusted.
func credToProto(c *identity.Credential) *dmcnpb.Credential {
	if c == nil {
		return nil
	}
	return c.ToProto()
}

func credFromProto(pb *dmcnpb.Credential) *identity.Credential {
	if pb == nil {
		return nil
	}
	c, err := identity.CredentialFromProto(pb)
	if err != nil {
		return nil
	}
	return c
}
