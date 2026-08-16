// Package identity implements the DMCN identity layer data structures
// and operations defined in whitepaper Section 15.2.
//
// An identity consists of an Ed25519 signing key pair and an X25519
// key exchange pair, bound together in a self-certifying IdentityRecord.
package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/dmcnpb"
	"google.golang.org/protobuf/proto"
)

// protoMarshal is the protobuf marshaling function, overridable for testing.
var protoMarshal = func(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

// Context-separation tags. Each is prepended to the canonical bytes before
// signing/verifying so a signature produced for one record type can never be
// reused as a signature for another (e.g. a domain countersignature replayed as
// an identity self-signature).
const (
	ctxIdentitySelf   = "dmcn-identity-self-v1\x00"
	ctxDARSelf        = "dmcn-dar-self-v1\x00"
	ctxAddressRemoval = "dmcn-address-removal-v1\x00"
	ctxKeyCompromise  = "dmcn-key-compromise-v1\x00"
	// ctxFleetRoster separates the fleet-roster self-signature (fleet domain root key
	// over the node roster) from every other record type.
	ctxFleetRoster = "dmcn-fleet-roster-v1\x00"
	// ctxCredential / ctxSubAuthorityRequest separate the unified Credential PKI
	// signatures (issuer cred signature; requester self-signed .sar) from every other
	// signature type, so none can be cross-replayed.
	ctxCredential          = "dmcn-credential-v1\x00"
	ctxSubAuthorityRequest = "dmcn-subauthority-request-v1\x00"
)

// signCtx signs ctx||data with priv.
func signCtx(priv ed25519.PrivateKey, ctx string, data []byte) ([]byte, error) {
	buf := make([]byte, 0, len(ctx)+len(data))
	buf = append(buf, ctx...)
	buf = append(buf, data...)
	return crypto.Sign(priv, buf)
}

// verifyCtx verifies sig over ctx||data against pub.
func verifyCtx(pub ed25519.PublicKey, ctx string, data, sig []byte) error {
	buf := make([]byte, 0, len(ctx)+len(data))
	buf = append(buf, ctx...)
	buf = append(buf, data...)
	return crypto.Verify(pub, buf, sig)
}

// fingerprintOf returns the 40-char uppercase hex of the first 20 bytes of
// SHA-256(ed||x). Shared by IdentityRecord and DomainAuthorityRecord so the
// _dmcn TXT format and domainverify work identically for both.
func fingerprintOf(ed ed25519.PublicKey, x [32]byte) string {
	data := make([]byte, 0, len(ed)+len(x))
	data = append(data, ed...)
	data = append(data, x[:]...)
	hash := crypto.SHA256Hash(data)
	return strings.ToUpper(hex.EncodeToString(hash[:20]))
}

var (
	// ErrInvalidAddress is returned when an address is malformed.
	ErrInvalidAddress = errors.New("identity: invalid address format")
	// ErrInvalidSignature is returned when a self-signature is invalid.
	ErrInvalidSignature = errors.New("identity: invalid self-signature")
	// ErrExpired is returned when an identity record has expired.
	ErrExpired = errors.New("identity: record expired")
)

// VerificationTier represents the level of identity verification.
// See whitepaper Section 15.2.2.
type VerificationTier int

const (
	TierUnverified VerificationTier = 0 // No verification
	// 1 is reserved (was TierProviderHosted — removed; provider-hosted address
	// claiming is not supported; see whitepaper Section 12 for rationale).
	TierDomainDNS VerificationTier = 2 // Domain DNS verification (Section 12.2.1)
	TierDANE      VerificationTier = 3 // DANE cryptographic binding (Section 12.2.2)
)

// String returns a human-readable name for the verification tier.
func (t VerificationTier) String() string {
	switch t {
	case TierUnverified:
		return "Unverified"
	case TierDomainDNS:
		return "DomainDNS"
	case TierDANE:
		return "DANE"
	default:
		return fmt.Sprintf("Tier(%d)", int(t))
	}
}

// IdentityKeyPair holds both the Ed25519 signing pair and the X25519 key
// exchange pair for a single identity, generated together at account creation.
//
// See whitepaper Section 15.2.1.
type IdentityKeyPair struct {
	Ed25519Public  ed25519.PublicKey
	Ed25519Private ed25519.PrivateKey
	X25519Public   [32]byte
	X25519Private  [32]byte
	CreatedAt      time.Time
	DeviceID       [16]byte
}

// GenerateIdentityKeyPair generates both key pairs in a single call.
// Private key material is never logged.
//
// See whitepaper Section 15.2.1.
func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	edPub, edPriv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	xPub, xPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	deviceID, err := crypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	return &IdentityKeyPair{
		Ed25519Public:  edPub,
		Ed25519Private: edPriv,
		X25519Public:   xPub,
		X25519Private:  xPriv,
		CreatedAt:      time.Now().UTC(),
		DeviceID:       deviceID,
	}, nil
}

// IdentityRecord maps a human-readable address to a key pair.
// It is self-certifying: the SelfSignature field covers all other fields
// and is produced by the identity's own Ed25519 private key.
//
// See whitepaper Section 15.2.2.
type IdentityRecord struct {
	Version          uint32
	Address          string // local@domain
	Ed25519Public    ed25519.PublicKey
	X25519Public     [32]byte
	CreatedAt        time.Time
	ExpiresAt        time.Time // zero = no expiry
	RelayHints       []string
	VerificationTier VerificationTier
	BridgeCapability bool
	RequireOnion     bool // mailbox owner requires inbound mail via onion routing
	// Revision is the owner-signed monotonic version of the identity core, bumped on every
	// owner re-sign. Covered by the self-signature (only the owner can advance it), it drives
	// fleet PutRecord + resolver anti-rollback so a stale record can't overwrite a newer one.
	Revision      uint64
	SelfSignature [64]byte

	// AddressCredential (Credential PKI) is the domain's attestation of this address↔key
	// binding (role "address"). Excluded from signableBytes/SelfSignature — the authority
	// issues it after the user self-signs (the dual binding).
	AddressCredential *Credential

	// RoutingCredential (Credential PKI) is the OPERATOR's attestation of this address's
	// mailbox routing (role "routing"), carrying the authoritative RelayHints. RelayHints
	// is operator-owned, so it is excluded from the owner SelfSignature and signed here
	// instead — letting an operator re-point/rebalance routing without the owner's key.
	// When present, its RelayHints are authoritative (mirrored into RelayHints on decode).
	RoutingCredential *Credential

	// OperatorCredentials (Credential PKI) are the OPERATOR's per-account attestations beyond
	// routing — the generic extension point (pb field 28). Like RoutingCredential they are
	// operator-owned: excluded from the owner SelfSignature and re-issuable without the owner's
	// key; the same-revision anti-rollback tiebreak uses the newest IssuedAt across
	// RoutingCredential and these. Semantics are identified by each credential's roles and
	// attributes — e.g. the product's send-rate limits ride a RoleQuota credential carrying an
	// "ext.rate_steps" attribute (see rate.go), operator/fleet-anchored so a BYOD tenant
	// cannot self-grant an abusive send rate.
	OperatorCredentials []*Credential
}

// HasAddressCredential reports whether a Credential-PKI address attestation is present.
func (r *IdentityRecord) HasAddressCredential() bool { return r.AddressCredential != nil }

// HasRoutingCredential reports whether an operator routing attestation is present.
func (r *IdentityRecord) HasRoutingCredential() bool { return r.RoutingCredential != nil }

// NOTE (open-dmcn reference implementation): the send-rate credential methods
// (HasRateCredential / SendRateCredential / IssueSendRateCredential) are a PRODUCT
// entitlement (ext.rate_steps rides the generic OperatorCredentials slot) and are
// omitted. OperatorCredentials itself stays — it is the core generic operator slot.

// NewIdentityRecord creates a new unsigned IdentityRecord from a key pair
// and address.
func NewIdentityRecord(address string, kp *IdentityKeyPair) (*IdentityRecord, error) {
	if err := validateAddress(address); err != nil {
		return nil, err
	}

	return &IdentityRecord{
		Version:          1,
		Address:          address,
		Ed25519Public:    kp.Ed25519Public,
		X25519Public:     kp.X25519Public,
		CreatedAt:        kp.CreatedAt,
		VerificationTier: TierUnverified,
		Revision:         1,
	}, nil
}

// Sign computes and sets the SelfSignature. The signed byte sequence is
// the canonical protobuf serialisation of all fields except SelfSignature.
//
// See whitepaper Section 15.2.2.
func (r *IdentityRecord) Sign(kp *IdentityKeyPair) error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: sign: %w", err)
	}

	sig, err := signCtx(kp.Ed25519Private, ctxIdentitySelf, data)
	if err != nil {
		return fmt.Errorf("identity: sign: %w", err)
	}

	copy(r.SelfSignature[:], sig)
	return nil
}

// Verify validates the SelfSignature against the record's Ed25519 public key.
// Returns nil if valid, ErrInvalidSignature if not.
//
// See whitepaper Section 15.2.2.
func (r *IdentityRecord) Verify() error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: verify: %w", err)
	}

	if err := verifyCtx(r.Ed25519Public, ctxIdentitySelf, data, r.SelfSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// Fingerprint returns the first 20 bytes of SHA-256(Ed25519Public || X25519Public),
// encoded as a 40-character uppercase hex string.
//
// Used for out-of-band identity verification.
// See whitepaper Section 15.2.1.
func (r *IdentityRecord) Fingerprint() string {
	return fingerprintOf(r.Ed25519Public, r.X25519Public)
}

// IssueAddressCredential attaches a Credential-PKI address attestation (role "address")
// to this record, signed by a domain authority key (root or a Grants:["address"]
// sub-authority). The record must already be self-signed by the user (the dual binding:
// user controls the key AND the domain assigned the address). Successor to Countersign.
func (r *IdentityRecord) IssueAddressCredential(issuer *IdentityKeyPair, at time.Time) error {
	cred := &Credential{
		Version:  1,
		Subject:  r.Ed25519Public,
		Domain:   domainverify.DomainOf(r.Address),
		Address:  r.Address,
		Roles:    []string{RoleAddress},
		IssuedAt: at.UTC(),
	}
	if err := cred.Sign(issuer); err != nil {
		return fmt.Errorf("identity: issue address credential: %w", err)
	}
	r.AddressCredential = cred
	return nil
}

// IssueRoutingCredential attaches a Credential-PKI routing attestation (role "routing")
// carrying the authoritative relay hints, signed by a domain authority key (root or a
// Grants:["routing"] sub-authority). RelayHints is operator-owned and excluded from the
// owner self-signature, so the operator can (re-)issue this — e.g. on rebalance — without
// the mailbox owner's key. Also mirrors hints into r.RelayHints for readers.
func (r *IdentityRecord) IssueRoutingCredential(issuer *IdentityKeyPair, hints []string, at time.Time) error {
	cred := &Credential{
		Version:    1,
		Subject:    r.Ed25519Public,
		Domain:     domainverify.DomainOf(r.Address),
		Address:    r.Address,
		Roles:      []string{RoleRouting},
		RelayHints: hints,
		IssuedAt:   at.UTC(),
	}
	if err := cred.Sign(issuer); err != nil {
		return fmt.Errorf("identity: issue routing credential: %w", err)
	}
	r.RoutingCredential = cred
	r.RelayHints = hints
	return nil
}

// signableBytes returns the canonical protobuf serialisation of the record
// with all fields except SelfSignature. This is the byte sequence over
// which the signature is computed.
func (r *IdentityRecord) signableBytes() ([]byte, error) {
	pb := &dmcnpb.IdentityRecord{
		Version:          r.Version,
		Address:          r.Address,
		Ed25519PublicKey: r.Ed25519Public,
		X25519PublicKey:  r.X25519Public[:],
		CreatedAt:        r.CreatedAt.Unix(),
		ExpiresAt:        unixOrZero(r.ExpiresAt),
		// RelayHints intentionally omitted — it is operator-owned (carried in the
		// RoutingCredential), not covered by the owner self-signature.
		VerificationTier: dmcnpb.VerificationTier(r.VerificationTier),
		BridgeCapability: r.BridgeCapability,
		RequireOnion:     r.RequireOnion,
		Revision:         r.Revision, // owner-signed monotonic version (anti-rollback)
		// SelfSignature intentionally omitted — this is what we sign over
	}

	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// unixOrZero returns t.Unix(), or 0 for the zero time — so "no expiry" serializes
// as 0 (a skipped proto3 field) rather than the zero time's large negative Unix
// value. This keeps the canonical bytes consistent with clients that send 0.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// ToProto converts the IdentityRecord to its protobuf representation.
func (r *IdentityRecord) ToProto() *dmcnpb.IdentityRecord {
	pb := &dmcnpb.IdentityRecord{
		Version:          r.Version,
		Address:          r.Address,
		Ed25519PublicKey: r.Ed25519Public,
		X25519PublicKey:  r.X25519Public[:],
		CreatedAt:        r.CreatedAt.Unix(),
		ExpiresAt:        unixOrZero(r.ExpiresAt),
		RelayHints:       r.RelayHints,
		VerificationTier: dmcnpb.VerificationTier(r.VerificationTier),
		BridgeCapability: r.BridgeCapability,
		RequireOnion:     r.RequireOnion,
		Revision:         r.Revision,
		SelfSignature:    r.SelfSignature[:],
	}
	if r.AddressCredential != nil {
		pb.AddressCredential = r.AddressCredential.ToProto()
	}
	if r.RoutingCredential != nil {
		pb.RoutingCredential = r.RoutingCredential.ToProto()
	}
	for _, c := range r.OperatorCredentials {
		if c != nil {
			pb.OperatorCredentials = append(pb.OperatorCredentials, c.ToProto())
		}
	}
	return pb
}

// IdentityRecordFromProto creates an IdentityRecord from its protobuf
// representation.
func IdentityRecordFromProto(pb *dmcnpb.IdentityRecord) (*IdentityRecord, error) {
	if pb == nil {
		return nil, errors.New("identity: nil protobuf record")
	}

	var x25519Pub [32]byte
	copy(x25519Pub[:], pb.X25519PublicKey)

	var selfSig [64]byte
	copy(selfSig[:], pb.SelfSignature)

	var expiresAt time.Time
	if pb.ExpiresAt != 0 {
		expiresAt = time.Unix(pb.ExpiresAt, 0).UTC()
	}

	rec := &IdentityRecord{
		Version:          pb.Version,
		Address:          pb.Address,
		Ed25519Public:    pb.Ed25519PublicKey,
		X25519Public:     x25519Pub,
		CreatedAt:        time.Unix(pb.CreatedAt, 0).UTC(),
		ExpiresAt:        expiresAt,
		RelayHints:       pb.RelayHints,
		VerificationTier: VerificationTier(pb.VerificationTier),
		BridgeCapability: pb.BridgeCapability,
		RequireOnion:     pb.RequireOnion,
		Revision:         pb.Revision,
		SelfSignature:    selfSig,
	}
	if pb.AddressCredential != nil {
		cred, err := CredentialFromProto(pb.AddressCredential)
		if err != nil {
			return nil, fmt.Errorf("identity: address credential: %w", err)
		}
		rec.AddressCredential = cred
	}
	if pb.RoutingCredential != nil {
		cred, err := CredentialFromProto(pb.RoutingCredential)
		if err != nil {
			return nil, fmt.Errorf("identity: routing credential: %w", err)
		}
		rec.RoutingCredential = cred
		// The routing credential carries the authoritative hints; mirror them so
		// readers can keep using rec.RelayHints (field 7 is only an unsigned mirror).
		rec.RelayHints = cred.RelayHints
	}
	for i, cpb := range pb.OperatorCredentials {
		if cpb == nil {
			continue
		}
		cred, err := CredentialFromProto(cpb)
		if err != nil {
			return nil, fmt.Errorf("identity: operator credential %d: %w", i, err)
		}
		rec.OperatorCredentials = append(rec.OperatorCredentials, cred)
	}
	return rec, nil
}

// IdentityRecordFromProtoBytes deserializes an IdentityRecord from raw
// protobuf bytes. This is a convenience wrapper used by the registry package.
func IdentityRecordFromProtoBytes(data []byte) (*IdentityRecord, error) {
	pb := &dmcnpb.IdentityRecord{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("identity: unmarshal: %w", err)
	}
	return IdentityRecordFromProto(pb)
}

// validateAddress performs basic validation on an address string.
// Addresses must be in local@domain format.
func validateAddress(address string) error {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%w: %q", ErrInvalidAddress, address)
	}
	return nil
}
