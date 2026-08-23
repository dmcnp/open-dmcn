// Domain Authority Records and address removal records (whitepaper Section 13).
//
// A DomainAuthorityRecord declares a domain's root authority key (proven via the
// _dmcn DNS TXT record carrying its fingerprint) plus the keys it authorizes to
// countersign addresses under the domain: the root key timeline (rotation
// history) and delegated sub-authorities. An AddressRemovalRecord is the
// root-signed tombstone that frees an address for re-binding.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"
	"google.golang.org/protobuf/proto"
)

// ErrInvalidDomain is returned when a domain string is malformed.
var ErrInvalidDomain = errors.New("identity: invalid domain")

// Domain policy bits carried in DomainAuthorityRecord.PolicyFlags (covered by the
// DAR self-signature). They are independent:
//
//   - PolicyRequireCountersign — an address on this domain is not usable until it
//     carries a valid domain countersignature (enforced at the relay FETCH path).
const (
	PolicyRequireCountersign uint32 = 1 << 0
	// Bit 1 is reserved for extensions (see SPEC.md §8).
	// PolicyRequireOnion: all addresses under the domain must receive mail via
	// onion routing (the relay rejects direct STOREs). See whitepaper Section 15.4.
	PolicyRequireOnion uint32 = 1 << 2
	// PolicyReplicateMailbox declares that an address's mail should be replicated across
	// all of its top-k routing relays rather than failover to the first reachable. When
	// set, senders STORE to every reachable relay hint (FETCH already merges + dedups).
	// Default off (failover).
	PolicyReplicateMailbox uint32 = 1 << 3
	// Bits 4 and above are reserved for extensions (see SPEC.md §8).
)

// DefaultReservedLocalParts is the reserved set written into a NEW domain's DAR at genesis
// (`dmcndcli domain init`). It is ONLY a seed — after creation the domain owner fully owns
// the list (DomainAuthorityRecord.ReservedLocalParts) and may add or remove any of these. It is
// NOT consulted at enforcement time (no hardcoded floor): an empty list means nothing reserved.
var DefaultReservedLocalParts = []string{
	"postmaster", "abuse", "hostmaster", "webmaster", "mailer-daemon", "mail", "smtp",
	"countersign", "authority", "admin", "root", "security",
	"no-reply", "noreply", "www", "contact",
}

// AuthorityKey is one entry in a domain root authority's key timeline. A key is
// effective from EffectiveFrom until the next key's EffectiveFrom; the latest
// key is open-ended. There is deliberately no end timestamp, so a key can never
// expire into a gap before its replacement exists.
type AuthorityKey struct {
	Ed25519Public  ed25519.PublicKey
	X25519Public   [32]byte
	EffectiveFrom  time.Time
	RotationReason uint32
}

// DomainAuthorityRecord declares a domain's authority key and the credentials it
// anchors (Credential PKI). Keyed in the DHT on SHA-256(domain).
type DomainAuthorityRecord struct {
	Version                uint32
	Domain                 string
	AuthorityEd25519       ed25519.PublicKey // CURRENT root key
	AuthorityX25519        [32]byte
	AuthorityEffectiveFrom time.Time
	SupersededKeys         []AuthorityKey
	PolicyFlags            uint32
	CreatedAt              time.Time
	Revision               uint64
	SelfSignature          [64]byte
	// AuthorityCredentials are the domain's authority/issuer credentials (Credential PKI) —
	// any role that carries delegation/issuance grants (e.g. a sub-authority, or a client
	// with the "routing"/"address" grants), at any delegation depth, so one cached DAR
	// fetch resolves any issuer in a chain.
	AuthorityCredentials []Credential
	// ReservedLocalParts are local-parts (case-insensitive) that may NOT be self-service
	// registered on this domain — seeded from DefaultReservedLocalParts at genesis, then fully
	// owner-owned (add/remove any entry). A reserved address requires the domain authority's
	// countersignature to become usable. Covered by the DAR self-signature. The sole source of
	// truth: empty ⇒ nothing reserved (there is no baseline floor).
	ReservedLocalParts []string
	// FleetDomain is the fleet domain this (mailbox) domain defers hosting to — email's MX
	// delegation. Empty ⇒ the domain runs its own nodes. It is the SIGNED mirror of the DNS
	// "fleet=" pointer: a resolver enforces DNS fleet== this value (fail-closed on mismatch), so
	// the authorized fleet is confirmed by the domain's own root key, not merely DNS-asserted.
	// Covered by the DAR self-signature.
	FleetDomain string
}

// ResolveAuthority returns the authority credential in the DAR whose Subject is pub,
// or nil. Used to walk a credential chain entirely from the cached DAR.
func (d *DomainAuthorityRecord) ResolveAuthority(pub ed25519.PublicKey) *Credential {
	for i := range d.AuthorityCredentials {
		if bytes.Equal(d.AuthorityCredentials[i].Subject, pub) {
			return &d.AuthorityCredentials[i]
		}
	}
	return nil
}

// NewDomainAuthorityRecord builds an unsigned genesis DAR for a domain, created
// (published) at `at`. The genesis root key is effective from when it was
// generated (root.CreatedAt), not from `at`: a key cannot countersign before it
// exists, so this is a safe lower bound that authorizes any countersignature the
// root makes regardless of when the DAR is published. Revision starts at 1.
func NewDomainAuthorityRecord(domain string, root *IdentityKeyPair, at time.Time) (*DomainAuthorityRecord, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	return &DomainAuthorityRecord{
		Version:                1,
		Domain:                 domain,
		AuthorityEd25519:       root.Ed25519Public,
		AuthorityX25519:        root.X25519Public,
		AuthorityEffectiveFrom: root.CreatedAt.UTC(),
		CreatedAt:              at.UTC(),
		Revision:               1,
	}, nil
}

// Fingerprint returns the fingerprint of the CURRENT root key — the value that
// must appear in the _dmcn.<domain> TXT record.
func (d *DomainAuthorityRecord) Fingerprint() string {
	return fingerprintOf(d.AuthorityEd25519, d.AuthorityX25519)
}

// RequiresCountersign reports whether addresses on this domain must carry a valid
// domain countersignature to be usable.
func (d *DomainAuthorityRecord) RequiresCountersign() bool {
	return d.PolicyFlags&PolicyRequireCountersign != 0
}

// RequiresOnion reports whether the domain mandates onion-routed delivery for all
// addresses under it.
func (d *DomainAuthorityRecord) RequiresOnion() bool {
	return d.PolicyFlags&PolicyRequireOnion != 0
}

// ReplicatesMailbox reports whether the domain declares mailbox replication across an
// address's top-k routing relays: senders STORE to every reachable relay hint (success if
// ≥1) rather than the first reachable. Default off (failover).
func (d *DomainAuthorityRecord) ReplicatesMailbox() bool {
	return d.PolicyFlags&PolicyReplicateMailbox != 0
}

// DefersToFleet reports the fleet domain this domain defers hosting to, and whether a deferral is
// set. When false, the domain runs its own nodes. Callers resolving an address use this (matched
// against the DNS "fleet=" pointer) to decide which fleet's seeds to bootstrap from.
func (d *DomainAuthorityRecord) DefersToFleet() (string, bool) {
	f := strings.ToLower(strings.TrimSpace(d.FleetDomain))
	return f, f != ""
}

// ReservesLocalPart reports whether localPart may NOT be self-service registered on this domain
// (it requires the domain authority's countersignature). Casefolds both sides — the query and
// each stored entry are lowercased and trimmed — so matching is case-insensitive regardless of how
// entries were stored. There is no baseline union: the DAR's ReservedLocalParts is the sole source
// of truth, so an empty list reserves nothing.
func (d *DomainAuthorityRecord) ReservesLocalPart(localPart string) bool {
	lp := strings.ToLower(strings.TrimSpace(localPart))
	if lp == "" {
		return false
	}
	for _, r := range d.ReservedLocalParts {
		if strings.ToLower(strings.TrimSpace(r)) == lp {
			return true
		}
	}
	return false
}

func (d *DomainAuthorityRecord) signableBytes() ([]byte, error) {
	pb := d.ToProto()
	pb.SelfSignature = nil
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// Sign sets SelfSignature using the CURRENT root private key.
func (d *DomainAuthorityRecord) Sign(root *IdentityKeyPair) error {
	data, err := d.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: dar sign: %w", err)
	}
	sig, err := signCtx(root.Ed25519Private, ctxDARSelf, data)
	if err != nil {
		return fmt.Errorf("identity: dar sign: %w", err)
	}
	copy(d.SelfSignature[:], sig)
	return nil
}

// Verify checks the self-signature against the current root key.
func (d *DomainAuthorityRecord) Verify() error {
	data, err := d.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: dar verify: %w", err)
	}
	if err := verifyCtx(d.AuthorityEd25519, ctxDARSelf, data, d.SelfSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// RootKeyAt returns the root key effective at time t: the one with the largest
// EffectiveFrom not after t, across the superseded keys and the current key. It
// returns false when t precedes the earliest key.
func (d *DomainAuthorityRecord) RootKeyAt(t time.Time) (ed25519.PublicKey, bool) {
	var best ed25519.PublicKey
	var bestFrom time.Time
	found := false
	consider := func(pub ed25519.PublicKey, from time.Time) {
		if from.After(t) {
			return
		}
		if !found || from.After(bestFrom) {
			best, bestFrom, found = pub, from, true
		}
	}
	for _, k := range d.SupersededKeys {
		consider(k.Ed25519Public, k.EffectiveFrom)
	}
	consider(d.AuthorityEd25519, d.AuthorityEffectiveFrom)
	return best, found
}

// ToProto converts the DAR to its protobuf representation.
func (d *DomainAuthorityRecord) ToProto() *dmcnpb.DomainAuthorityRecord {
	pb := &dmcnpb.DomainAuthorityRecord{
		Version:                   d.Version,
		Domain:                    d.Domain,
		AuthorityEd25519PublicKey: d.AuthorityEd25519,
		AuthorityX25519PublicKey:  d.AuthorityX25519[:],
		AuthorityEffectiveFrom:    d.AuthorityEffectiveFrom.Unix(),
		PolicyFlags:               d.PolicyFlags,
		CreatedAt:                 d.CreatedAt.Unix(),
		Revision:                  d.Revision,
		SelfSignature:             d.SelfSignature[:],
		ReservedLocalParts:        d.ReservedLocalParts,
		FleetDomain:               d.FleetDomain,
	}
	for _, k := range d.SupersededKeys {
		x := k.X25519Public
		pb.SupersededKeys = append(pb.SupersededKeys, &dmcnpb.AuthorityKey{
			Ed25519PublicKey: k.Ed25519Public,
			X25519PublicKey:  x[:],
			EffectiveFrom:    k.EffectiveFrom.Unix(),
			RotationReason:   k.RotationReason,
		})
	}
	for i := range d.AuthorityCredentials {
		pb.AuthorityCredentials = append(pb.AuthorityCredentials, d.AuthorityCredentials[i].ToProto())
	}
	return pb
}

// DomainAuthorityRecordFromProto builds a DAR from its protobuf representation.
func DomainAuthorityRecordFromProto(pb *dmcnpb.DomainAuthorityRecord) (*DomainAuthorityRecord, error) {
	if pb == nil {
		return nil, errors.New("identity: nil DAR protobuf")
	}
	d := &DomainAuthorityRecord{
		Version:                pb.Version,
		Domain:                 pb.Domain,
		AuthorityEd25519:       pb.AuthorityEd25519PublicKey,
		AuthorityEffectiveFrom: time.Unix(pb.AuthorityEffectiveFrom, 0).UTC(),
		PolicyFlags:            pb.PolicyFlags,
		CreatedAt:              time.Unix(pb.CreatedAt, 0).UTC(),
		Revision:               pb.Revision,
		// NOT normalized here — Verify() re-marshals ToProto(), so the bytes must round-trip
		// faithfully. Casefolding happens at write time (CLI) and at compare time
		// (ReservesLocalPart).
		ReservedLocalParts: append([]string(nil), pb.ReservedLocalParts...),
		FleetDomain:        pb.FleetDomain,
	}
	copy(d.AuthorityX25519[:], pb.AuthorityX25519PublicKey)
	copy(d.SelfSignature[:], pb.SelfSignature)
	for _, k := range pb.SupersededKeys {
		ak := AuthorityKey{
			Ed25519Public:  k.Ed25519PublicKey,
			EffectiveFrom:  time.Unix(k.EffectiveFrom, 0).UTC(),
			RotationReason: k.RotationReason,
		}
		copy(ak.X25519Public[:], k.X25519PublicKey)
		d.SupersededKeys = append(d.SupersededKeys, ak)
	}
	for _, c := range pb.AuthorityCredentials {
		cred, err := CredentialFromProto(c)
		if err != nil {
			return nil, fmt.Errorf("identity: dar authority credential: %w", err)
		}
		d.AuthorityCredentials = append(d.AuthorityCredentials, *cred)
	}
	return d, nil
}

// DomainAuthorityRecordFromProtoBytes deserializes a DAR from raw protobuf bytes.
func DomainAuthorityRecordFromProtoBytes(data []byte) (*DomainAuthorityRecord, error) {
	pb := &dmcnpb.DomainAuthorityRecord{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("identity: dar unmarshal: %w", err)
	}
	return DomainAuthorityRecordFromProto(pb)
}

// RemovedBinding tombstones a specific prior (address, user key) binding.
type RemovedBinding struct {
	Ed25519Public ed25519.PublicKey
	RemovedAt     time.Time
}

// AddressRemovalRecord is the root-signed, append-only list of removed bindings
// for one address. Keyed in the DHT on SHA-256(address). Only the domain root
// can publish one.
type AddressRemovalRecord struct {
	Version         uint32
	Domain          string
	Address         string
	RemovedBindings []RemovedBinding
	Revision        uint64
	CreatedAt       time.Time
	SelfSignature   [64]byte
}

// NewAddressRemovalRecord builds an unsigned, empty removal record for an
// address created at `at`. Revision starts at 1.
func NewAddressRemovalRecord(domain, address string, at time.Time) (*AddressRemovalRecord, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if err := validateAddress(address); err != nil {
		return nil, err
	}
	return &AddressRemovalRecord{Version: 1, Domain: domain, Address: address, Revision: 1, CreatedAt: at.UTC()}, nil
}

func (a *AddressRemovalRecord) signableBytes() ([]byte, error) {
	pb := a.ToProto()
	pb.SelfSignature = nil
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// Sign sets SelfSignature using the domain root private key.
func (a *AddressRemovalRecord) Sign(root *IdentityKeyPair) error {
	data, err := a.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: removal sign: %w", err)
	}
	sig, err := signCtx(root.Ed25519Private, ctxAddressRemoval, data)
	if err != nil {
		return fmt.Errorf("identity: removal sign: %w", err)
	}
	copy(a.SelfSignature[:], sig)
	return nil
}

// Verify checks the self-signature against the supplied root public key (the
// caller selects the root key effective when the record was signed).
func (a *AddressRemovalRecord) Verify(rootPub ed25519.PublicKey) error {
	data, err := a.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: removal verify: %w", err)
	}
	if err := verifyCtx(rootPub, ctxAddressRemoval, data, a.SelfSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// Removed reports whether the given user identity key has been tombstoned for
// this address, returning the removal time.
func (a *AddressRemovalRecord) Removed(ed ed25519.PublicKey) (time.Time, bool) {
	for _, b := range a.RemovedBindings {
		if bytes.Equal(b.Ed25519Public, ed) {
			return b.RemovedAt, true
		}
	}
	return time.Time{}, false
}

// ToProto converts the removal record to its protobuf representation.
func (a *AddressRemovalRecord) ToProto() *dmcnpb.AddressRemovalRecord {
	pb := &dmcnpb.AddressRemovalRecord{
		Version:       a.Version,
		Domain:        a.Domain,
		Address:       a.Address,
		Revision:      a.Revision,
		CreatedAt:     a.CreatedAt.Unix(),
		SelfSignature: a.SelfSignature[:],
	}
	for _, b := range a.RemovedBindings {
		pb.RemovedBindings = append(pb.RemovedBindings, &dmcnpb.RemovedBinding{
			Ed25519PublicKey: b.Ed25519Public,
			RemovedAt:        b.RemovedAt.Unix(),
		})
	}
	return pb
}

// AddressRemovalRecordFromProto builds a removal record from protobuf.
func AddressRemovalRecordFromProto(pb *dmcnpb.AddressRemovalRecord) (*AddressRemovalRecord, error) {
	if pb == nil {
		return nil, errors.New("identity: nil removal protobuf")
	}
	a := &AddressRemovalRecord{
		Version:   pb.Version,
		Domain:    pb.Domain,
		Address:   pb.Address,
		Revision:  pb.Revision,
		CreatedAt: time.Unix(pb.CreatedAt, 0).UTC(),
	}
	copy(a.SelfSignature[:], pb.SelfSignature)
	for _, b := range pb.RemovedBindings {
		a.RemovedBindings = append(a.RemovedBindings, RemovedBinding{
			Ed25519Public: b.Ed25519PublicKey,
			RemovedAt:     time.Unix(b.RemovedAt, 0).UTC(),
		})
	}
	return a, nil
}

// AddressRemovalRecordFromProtoBytes deserializes a removal record from bytes.
func AddressRemovalRecordFromProtoBytes(data []byte) (*AddressRemovalRecord, error) {
	pb := &dmcnpb.AddressRemovalRecord{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("identity: removal unmarshal: %w", err)
	}
	return AddressRemovalRecordFromProto(pb)
}

// validateDomain performs basic validation: non-empty and no '@'.
func validateDomain(domain string) error {
	if domain == "" || bytes.ContainsRune([]byte(domain), '@') {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, domain)
	}
	return nil
}
