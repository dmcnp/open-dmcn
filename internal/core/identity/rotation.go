package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/domainverify"
)

// MaxRotationChain bounds the rotation chain carried ON an IdentityRecord.
//
// The record is re-marshaled on every republish and re-verified on every resolve, so an
// unbounded history would make both costs grow with the account's age. The complete history
// lives in the address's AddressHistoryRecord instead, and a reader whose pinned key falls
// outside this window resolves that record rather than giving up.
//
// Truncation is deliberately VISIBLE: the oldest retained entry keeps a PrevSignatureHash
// naming an entry that is absent, which ChainTruncated reports and a reader weighs
// differently from a genuine genesis. See SPEC.md §1.
const MaxRotationChain = 8

var (
	// ErrRotationChainInvalid: the chain is present and does not hold together. A record
	// carrying one is asserting a history nobody signed, so readers drop it to
	// TierUnverified rather than treating it as merely un-rotated.
	ErrRotationChainInvalid = errors.New("identity: rotation chain does not verify")
	// ErrRotationChainTooLong: more entries than MaxRotationChain.
	ErrRotationChainTooLong = errors.New("identity: rotation chain exceeds the retained window")
)

// RotationEntry is one owner-authorized transition from one account keypair to the next.
//
// Two signatures, because one proves only half of a handover:
//
//	Signature     — by AuthorizingEd25519Public (the retiring key, or the owner's recovery
//	                key), proving the outgoing holder consented to give the address up;
//	NextSignature — by NextEd25519Public, proving the incoming key accepted it.
//
// Consent alone would let an entry be minted that points a lineage at a key which never
// agreed. Inside an IdentityRecord the owner self-signature would close that, but entries are
// also read detached — from an AddressHistoryRecord, and over the directory API — so both
// travel with the entry.
type RotationEntry struct {
	Version uint32
	Address string

	RetiredEd25519Public ed25519.PublicKey
	RetiredX25519Public  [32]byte
	NextEd25519Public    ed25519.PublicKey
	NextX25519Public     [32]byte

	RotatedAt    time.Time
	NextRevision uint64

	// PrevSignatureHash is SHA-256 of the preceding entry's Signature, or nil at genesis.
	// It is what makes front-truncation detectable rather than silent.
	PrevSignatureHash []byte

	// AuthorizingEd25519Public produced Signature: normally RetiredEd25519Public, or the
	// owner's recovery key when the active key was gone. Named on the entry so history stays
	// verifiable detached — a reader holds no prior record and could not otherwise learn
	// which recovery key was enrolled. Whether a recovery key was genuinely the enrolled one
	// is settled at admission, where the relay does hold the record being displaced.
	AuthorizingEd25519Public ed25519.PublicKey

	// DeviceCredential attests that an enrolled device authorized this rotation. Its IssuedAt
	// fixes the device's enrollment time, so a node weighs tenure without mailbox state.
	DeviceCredential *Credential

	// DeviceSignature is by DeviceCredential.Subject over the transition. The credential alone
	// would prove nothing: it is public once any entry carrying it is published, so an attacker
	// holding the ACCOUNT key could lift one from an earlier transition. The device's own
	// signature over THIS transition is what a stolen account key cannot produce, because
	// device keys are generated on their device and are absent from the backup export and the
	// pairing payload.
	DeviceSignature []byte

	// The three signatures NEST, each covering the ones before it, so none can be lifted from
	// one transition and pasted onto another.
	Signature     []byte
	NextSignature []byte
}

// RecoverySigned reports whether this transition was authorized by a key other than the one
// being retired — i.e. by the owner's recovery key. Callers that hold the record being
// displaced check the key against its RecoveryEd25519Public; readers walking history surface
// it, since a recovery-signed transition means the active key was already lost.
func (e *RotationEntry) RecoverySigned() bool {
	return len(e.AuthorizingEd25519Public) > 0 &&
		!bytes.Equal(e.AuthorizingEd25519Public, e.RetiredEd25519Public)
}

// deviceBytes are fields 1-11: the transition itself, with no signature over it yet. This is
// what the enrolled device signs to bind itself to THIS handover.
func (e *RotationEntry) deviceBytes() ([]byte, error) {
	pb := e.ToProto()
	pb.DeviceSignature = nil
	pb.Signature = nil
	pb.NextSignature = nil
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// consentBytes are fields 1-12: the transition plus the device attestation, so the outgoing key
// consents to a handover that already names which device asked for it.
func (e *RotationEntry) consentBytes() ([]byte, error) {
	pb := e.ToProto()
	pb.Signature = nil
	pb.NextSignature = nil
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// acceptBytes are fields 1-13: the consent bytes plus the consent signature, so the incoming
// key countersigns the exact handover the outgoing key offered.
func (e *RotationEntry) acceptBytes() ([]byte, error) {
	pb := e.ToProto()
	pb.NextSignature = nil
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// SignDevice sets DeviceSignature with the enrolled device's key, binding that device to this
// transition. Call it FIRST — consent covers it, and acceptance covers consent.
//
// AuthorizingEd25519Public must already be set, because the device signs over it: the device is
// attesting to this handover AS AUTHORIZED BY THAT KEY, and a key decided afterwards would move
// the bytes out from under a signature already given.
func (e *RotationEntry) SignDevice(devicePriv ed25519.PrivateKey) error {
	if len(e.AuthorizingEd25519Public) == 0 {
		return errors.New("identity: rotation device attestation: set AuthorizingEd25519Public first")
	}
	data, err := e.deviceBytes()
	if err != nil {
		return fmt.Errorf("identity: rotation device attestation: %w", err)
	}
	sig, err := signCtx(devicePriv, ctxIdentityRotationDevice, data)
	if err != nil {
		return fmt.Errorf("identity: rotation device attestation: %w", err)
	}
	e.DeviceSignature = sig
	return nil
}

// SignConsent sets Signature with the key giving the address up — the retiring key, or the
// owner's recovery key.
//
// It CHECKS AuthorizingEd25519Public rather than assigning it. Assigning here would silently
// move field 10 after the device had already signed over it, invalidating an attestation the
// caller believed it had; a recovery-signed rotation therefore declares its authorizing key when
// the entry is built.
func (e *RotationEntry) SignConsent(kp *IdentityKeyPair) error {
	if !bytes.Equal(e.AuthorizingEd25519Public, kp.Ed25519Public) {
		return errors.New("identity: rotation consent: this key is not the entry's authorizing key")
	}
	data, err := e.consentBytes()
	if err != nil {
		return fmt.Errorf("identity: rotation consent: %w", err)
	}
	sig, err := signCtx(kp.Ed25519Private, ctxIdentityRotation, data)
	if err != nil {
		return fmt.Errorf("identity: rotation consent: %w", err)
	}
	e.Signature = sig
	return nil
}

// SignAcceptance sets NextSignature with the key taking the address over. Call it after
// SignConsent — the acceptance covers the consent signature, so signing in the other order
// produces an entry that fails verification.
func (e *RotationEntry) SignAcceptance(kp *IdentityKeyPair) error {
	if len(e.Signature) == 0 {
		return errors.New("identity: rotation acceptance: sign consent first")
	}
	data, err := e.acceptBytes()
	if err != nil {
		return fmt.Errorf("identity: rotation acceptance: %w", err)
	}
	sig, err := signCtx(kp.Ed25519Private, ctxIdentityRotationAccept, data)
	if err != nil {
		return fmt.Errorf("identity: rotation acceptance: %w", err)
	}
	e.NextSignature = sig
	return nil
}

// Verify checks both signatures and the entry's internal shape. It establishes that the
// named outgoing key consented and the named incoming key accepted; it says nothing about
// whether this entry belongs where it was found, which VerifyRotationChain decides.
func (e *RotationEntry) Verify() error {
	if e.Version == 0 {
		return fmt.Errorf("%w: version is unset", ErrRotationChainInvalid)
	}
	if err := validateAddress(e.Address); err != nil {
		return fmt.Errorf("%w: %v", ErrRotationChainInvalid, err)
	}
	for name, k := range map[string]ed25519.PublicKey{
		"retired":     e.RetiredEd25519Public,
		"next":        e.NextEd25519Public,
		"authorizing": e.AuthorizingEd25519Public,
	} {
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: %s key is %d bytes, want %d", ErrRotationChainInvalid, name, len(k), ed25519.PublicKeySize)
		}
	}
	// A transition to the key already held is not a transition, and admitting one would let
	// an entry be replayed as a no-op that still advances the chain.
	if bytes.Equal(e.RetiredEd25519Public, e.NextEd25519Public) {
		return fmt.Errorf("%w: retired and next keys are the same", ErrRotationChainInvalid)
	}
	if e.RetiredX25519Public == e.NextX25519Public {
		return fmt.Errorf("%w: retired and next mailbox keys are the same", ErrRotationChainInvalid)
	}
	if e.RotatedAt.IsZero() {
		return fmt.Errorf("%w: rotated_at is unset", ErrRotationChainInvalid)
	}
	if e.NextRevision == 0 {
		return fmt.Errorf("%w: next_revision is unset", ErrRotationChainInvalid)
	}
	if n := len(e.PrevSignatureHash); n != 0 && n != crypto.SHA256Size {
		return fmt.Errorf("%w: prev_signature_hash is %d bytes, want 0 or %d", ErrRotationChainInvalid, n, crypto.SHA256Size)
	}

	consent, err := e.consentBytes()
	if err != nil {
		return err
	}
	if err := verifyCtx(e.AuthorizingEd25519Public, ctxIdentityRotation, consent, e.Signature); err != nil {
		return fmt.Errorf("%w: the outgoing key did not consent to this transition", ErrRotationChainInvalid)
	}
	// The device attestation is verified STRUCTURALLY here — the named device signed this
	// transition. Whether that credential chains to the domain, is unexpired, and clears the
	// domain's tenure minimum is an ADMISSION-time question about the terminal entry, asked in
	// AuthorizeRebind against the rotation's own time. Re-asking it during a history walk would
	// fail every past entry the moment its credential expired.
	if e.DeviceCredential != nil {
		device, derr := e.deviceBytes()
		if derr != nil {
			return derr
		}
		if verr := verifyCtx(e.DeviceCredential.Subject, ctxIdentityRotationDevice, device, e.DeviceSignature); verr != nil {
			return fmt.Errorf("%w: the named device did not attest this transition", ErrRotationChainInvalid)
		}
	} else if len(e.DeviceSignature) > 0 {
		return fmt.Errorf("%w: a device signature with no credential names no device", ErrRotationChainInvalid)
	}

	accept, err := e.acceptBytes()
	if err != nil {
		return err
	}
	if err := verifyCtx(e.NextEd25519Public, ctxIdentityRotationAccept, accept, e.NextSignature); err != nil {
		return fmt.Errorf("%w: the incoming key did not accept this transition", ErrRotationChainInvalid)
	}
	return nil
}

// ToProto converts the entry to its protobuf representation.
func (e *RotationEntry) ToProto() *dmcnpb.RotationEntry {
	pb := &dmcnpb.RotationEntry{
		Version:                     e.Version,
		Address:                     e.Address,
		RetiredEd25519PublicKey:     e.RetiredEd25519Public,
		RetiredX25519PublicKey:      e.RetiredX25519Public[:],
		NextEd25519PublicKey:        e.NextEd25519Public,
		NextX25519PublicKey:         e.NextX25519Public[:],
		RotatedAt:                   e.RotatedAt.Unix(),
		NextRevision:                e.NextRevision,
		PrevSignatureHash:           e.PrevSignatureHash,
		AuthorizingEd25519PublicKey: e.AuthorizingEd25519Public,
		DeviceSignature:             e.DeviceSignature,
		Signature:                   e.Signature,
		NextSignature:               e.NextSignature,
	}
	if e.DeviceCredential != nil {
		pb.DeviceCredential = e.DeviceCredential.ToProto()
	}
	return pb
}

// RotationEntryFromProto converts a protobuf rotation entry into its Go representation.
func RotationEntryFromProto(pb *dmcnpb.RotationEntry) (*RotationEntry, error) {
	if pb == nil {
		return nil, errors.New("identity: nil rotation entry")
	}
	e := &RotationEntry{
		Version:                  pb.Version,
		Address:                  pb.Address,
		RetiredEd25519Public:     pb.RetiredEd25519PublicKey,
		NextEd25519Public:        pb.NextEd25519PublicKey,
		RotatedAt:                time.Unix(pb.RotatedAt, 0).UTC(),
		NextRevision:             pb.NextRevision,
		PrevSignatureHash:        pb.PrevSignatureHash,
		AuthorizingEd25519Public: pb.AuthorizingEd25519PublicKey,
		DeviceSignature:          pb.DeviceSignature,
		Signature:                pb.Signature,
		NextSignature:            pb.NextSignature,
	}
	if len(pb.RetiredX25519PublicKey) != 32 {
		return nil, fmt.Errorf("identity: rotation entry retired x25519 key is %d bytes, want 32", len(pb.RetiredX25519PublicKey))
	}
	copy(e.RetiredX25519Public[:], pb.RetiredX25519PublicKey)
	if len(pb.NextX25519PublicKey) != 32 {
		return nil, fmt.Errorf("identity: rotation entry next x25519 key is %d bytes, want 32", len(pb.NextX25519PublicKey))
	}
	copy(e.NextX25519Public[:], pb.NextX25519PublicKey)
	if pb.DeviceCredential != nil {
		cred, err := CredentialFromProto(pb.DeviceCredential)
		if err != nil {
			return nil, fmt.Errorf("identity: rotation entry device credential: %w", err)
		}
		e.DeviceCredential = cred
	}
	return e, nil
}

// ChainTruncated reports whether a chain begins part-way through an address's history: its
// oldest entry names a predecessor that is absent. A complete chain starts at the address's
// first rotation, whose PrevSignatureHash is empty.
//
// This is the signal that sends a reader to the AddressHistoryRecord, and the reason a pinned
// key missing from a truncated chain means "look further" rather than "never happened".
func ChainTruncated(chain []RotationEntry) bool {
	return len(chain) > 0 && len(chain[0].PrevSignatureHash) > 0
}

// verifyChainLinks walks a chain on its own terms: every entry valid, belonging to this address,
// and continuing the one before it.
//
// Shared by the chain carried ON a record and by the complete history served beside it, because
// they are the same chain seen through two windows — one capped for the hot path, one whole. A
// second copy of these rules is a second place for them to drift.
func verifyChainLinks(chain []RotationEntry, address string) error {
	for i := range chain {
		e := &chain[i]
		if err := e.Verify(); err != nil {
			return fmt.Errorf("rotation chain entry %d: %w", i, err)
		}
		// Every entry names the address it belongs to, so a transition genuinely signed for one
		// address cannot be replayed into another address's history.
		if !strings.EqualFold(e.Address, address) {
			return fmt.Errorf("%w: entry %d is for %q, not %q", ErrRotationChainInvalid, i, e.Address, address)
		}
		if i == 0 {
			continue
		}
		prev := &chain[i-1]
		if !bytes.Equal(e.RetiredEd25519Public, prev.NextEd25519Public) ||
			e.RetiredX25519Public != prev.NextX25519Public {
			return fmt.Errorf("%w: entry %d retires a key entry %d did not hand over", ErrRotationChainInvalid, i, i-1)
		}
		if prevHash := crypto.SHA256Hash(prev.Signature); !bytes.Equal(e.PrevSignatureHash, prevHash[:]) {
			return fmt.Errorf("%w: entry %d does not chain to entry %d", ErrRotationChainInvalid, i, i-1)
		}
		if !e.RotatedAt.After(prev.RotatedAt) {
			return fmt.Errorf("%w: entry %d is not after entry %d in time", ErrRotationChainInvalid, i, i-1)
		}
		if e.NextRevision <= prev.NextRevision {
			return fmt.Errorf("%w: entry %d revision %d does not advance past %d", ErrRotationChainInvalid, i, e.NextRevision, prev.NextRevision)
		}
	}
	return nil
}

// VerifyRotationChain walks the chain carried on a record and reports whether it holds
// together as that record's own history.
//
// An empty chain is valid and means the address has never rotated. Otherwise every entry must
// verify on its own, each must continue the one before it, and the last must land exactly on
// the keys and revision this record publishes — which is what stops a genuine chain being
// spliced onto a record it never belonged to.
//
// The chain proves CONTINUITY, and deliberately not origin: it says each key handed the
// address to the next, leaving "was the first key ever really this person" to an observer who
// saw it. See SPEC.md §1.
func VerifyRotationChain(rec *IdentityRecord) error {
	if rec == nil {
		return errors.New("identity: no record to verify")
	}
	chain := rec.RotationChain
	if len(chain) == 0 {
		return nil
	}
	if len(chain) > MaxRotationChain {
		return fmt.Errorf("%w: %d entries, limit %d", ErrRotationChainTooLong, len(chain), MaxRotationChain)
	}

	if err := verifyChainLinks(chain, rec.Address); err != nil {
		return err
	}

	// The terminal entry must land on this record. Without this a valid chain ending in some
	// other key could be carried by any record at all.
	last := &chain[len(chain)-1]
	if !bytes.Equal(last.NextEd25519Public, rec.Ed25519Public) || last.NextX25519Public != rec.X25519Public {
		return fmt.Errorf("%w: the last transition hands over to a different key than this record publishes", ErrRotationChainInvalid)
	}
	if last.NextRevision != rec.Revision {
		return fmt.Errorf("%w: the last transition mints revision %d, this record is revision %d", ErrRotationChainInvalid, last.NextRevision, rec.Revision)
	}
	return nil
}

// RecordAcceptsSubject reports whether a credential naming `subject` still applies to this
// record's account.
//
// The current key always qualifies. A RETIRED key qualifies only for credentials issued
// BEFORE the rotation that retired it, which is what lets an operator grant minted earlier —
// a quota, an access entitlement — survive a rotation and be re-pushed by a drain, a billing
// retry or a replica repair, while a grant minted afterwards against a dead key is refused.
//
// The caller verifies the chain first; an unverified chain must never widen what a credential
// may claim.
func RecordAcceptsSubject(rec *IdentityRecord, subject []byte, issuedAt time.Time) bool {
	if rec == nil || len(subject) == 0 {
		return false
	}
	if bytes.Equal(subject, rec.Ed25519Public) {
		return true
	}
	for i := range rec.RotationChain {
		e := &rec.RotationChain[i]
		if bytes.Equal(subject, e.RetiredEd25519Public) {
			return issuedAt.Before(e.RotatedAt)
		}
	}
	return false
}

// RotatedFrom reports whether `pub` appears in this record's chain as a key the account used
// to hold, and when it handed over. It is the reader-side question behind a key-change
// prompt: a pinned key found here means the counterparty rotated and said so, rather than
// having been substituted.
//
// A false answer on a TRUNCATED chain is inconclusive — the pin may predate the retained
// window — so callers check ChainTruncated before treating it as "never held".
func RotatedFrom(rec *IdentityRecord, pub ed25519.PublicKey) (time.Time, bool) {
	if rec == nil || len(pub) == 0 {
		return time.Time{}, false
	}
	for i := range rec.RotationChain {
		if bytes.Equal(rec.RotationChain[i].RetiredEd25519Public, pub) {
			return rec.RotationChain[i].RotatedAt, true
		}
	}
	return time.Time{}, false
}

// rotationChainProto renders the chain for marshaling. It returns nil for an empty chain so
// the encoded bytes of a record that has never rotated stay byte-identical to what every
// client produced before this field existed — the precondition for adding a signed core
// field at all (CLAUDE.md, "Adding a signed core field").
func (r *IdentityRecord) rotationChainProto() []*dmcnpb.RotationEntry {
	if len(r.RotationChain) == 0 {
		return nil
	}
	out := make([]*dmcnpb.RotationEntry, 0, len(r.RotationChain))
	for i := range r.RotationChain {
		out = append(out, r.RotationChain[i].ToProto())
	}
	return out
}

// rotationChainFromProto decodes a chain, rejecting any entry that is structurally unusable.
func rotationChainFromProto(pbs []*dmcnpb.RotationEntry) ([]RotationEntry, error) {
	if len(pbs) == 0 {
		return nil, nil
	}
	out := make([]RotationEntry, 0, len(pbs))
	for i, pb := range pbs {
		e, err := RotationEntryFromProto(pb)
		if err != nil {
			return nil, fmt.Errorf("rotation chain entry %d: %w", i, err)
		}
		out = append(out, *e)
	}
	return out, nil
}

// NewRotationEntry builds an unsigned transition from `prev` (the record being replaced) to
// the keys `next` publishes. The caller signs consent with the retiring or recovery key, then
// acceptance with the new one.
func NewRotationEntry(prev *IdentityRecord, nextEd ed25519.PublicKey, nextX [32]byte, nextRevision uint64, at time.Time) (*RotationEntry, error) {
	if prev == nil {
		return nil, errors.New("identity: no record to rotate from")
	}
	if nextRevision <= prev.Revision {
		return nil, fmt.Errorf("identity: rotation revision %d must advance past %d", nextRevision, prev.Revision)
	}
	e := &RotationEntry{
		Version:              1,
		Address:              prev.Address,
		RetiredEd25519Public: prev.Ed25519Public,
		RetiredX25519Public:  prev.X25519Public,
		NextEd25519Public:    nextEd,
		NextX25519Public:     nextX,
		RotatedAt:            at.UTC(),
		NextRevision:         nextRevision,
	}
	// Default the authorizing key to the one being retired, which is every rotation but a
	// recovery. A caller re-keying from a recovery key overwrites this BEFORE signing anything,
	// since the device attestation and the consent both cover it.
	e.AuthorizingEd25519Public = prev.Ed25519Public
	// Chain to whatever history `prev` carried, so the new entry continues it rather than
	// starting a fresh one. An empty hash here means this is genuinely the address's first
	// rotation, which is what ChainTruncated reads.
	if n := len(prev.RotationChain); n > 0 {
		h := crypto.SHA256Hash(prev.RotationChain[n-1].Signature)
		e.PrevSignatureHash = h[:]
	}
	return e, nil
}

// AppendRotation returns prev's chain extended by `e` and trimmed to MaxRotationChain,
// dropping the oldest links first. The dropped tail stays available in the address's
// AddressHistoryRecord.
func AppendRotation(prev *IdentityRecord, e *RotationEntry) []RotationEntry {
	var chain []RotationEntry
	if prev != nil {
		chain = append(chain, prev.RotationChain...)
	}
	chain = append(chain, *e)
	if len(chain) > MaxRotationChain {
		chain = chain[len(chain)-MaxRotationChain:]
	}
	return chain
}

// --- The per-account transparency log --------------------------------------------------------

// AddressHistoryRecord is one address's complete rotation history, served by its domain's fleet.
//
// The IdentityRecord carries a capped window of the same chain for the hot path; this holds all of
// it, so a key change stays auditable however many rotations follow. Between them they are what
// makes a rotation publicly evidence-producing rather than evidence only to whoever already held a
// pin — a counterparty meeting an address for the first time can read how it got here.
//
// It carries NO signature of its own, and needs none. Every entry is already signed by the key it
// retires and by the key taking over, so integrity comes from the entries: extending this record
// takes keys the extender must genuinely hold. A container signature would add a second thing to
// check and nothing to learn.
//
// What it is NOT: a substitute for the gossiped transparency log. This is self-certifying to
// whoever reads it, and says nothing about whether every reader was shown the same history —
// which is the one thing only cross-observer consistency can establish.
type AddressHistoryRecord struct {
	Version uint32
	Domain  string
	Address string
	// Chain is the complete history, oldest first, beginning at the address's first rotation.
	Chain []RotationEntry
}

// NewAddressHistoryRecord builds an empty history for an address.
func NewAddressHistoryRecord(domain, address string) (*AddressHistoryRecord, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if err := validateAddress(address); err != nil {
		return nil, err
	}
	return &AddressHistoryRecord{Version: 1, Domain: domain, Address: address}, nil
}

// Verify checks that the history holds together on its own terms: every entry signed by both the
// key it retires and the key taking over, each continuing the one before it, and none of it
// claiming to belong to another address.
//
// Deliberately says nothing about the address's CURRENT keys. A history is a record of what
// happened, and a reader holding a record newer than this one is looking at a stale copy rather
// than a broken one. Agreement with the live record is checked where it matters — at admission,
// by a node that holds both.
func (h *AddressHistoryRecord) Verify() error {
	if h == nil {
		return errors.New("identity: no history to verify")
	}
	if err := validateAddress(h.Address); err != nil {
		return err
	}
	if !strings.EqualFold(h.Domain, domainverify.DomainOf(h.Address)) {
		return fmt.Errorf("%w: history domain %q is not %q's", ErrRotationChainInvalid, h.Domain, h.Address)
	}
	// A complete history starts at the address's FIRST rotation, so its oldest entry has no
	// predecessor. A truncated one here would defeat the record's whole purpose: this is where a
	// reader comes when the capped on-record chain already fell short.
	if ChainTruncated(h.Chain) {
		return fmt.Errorf("%w: a history record must begin at the first rotation", ErrRotationChainInvalid)
	}
	return verifyChainLinks(h.Chain, h.Address)
}

// Extends reports whether `h` continues `prior` — every entry `prior` holds, in order, followed by
// at least one more.
//
// This is the admission rule, and it is what makes the record append-only in practice: a history
// may only grow, so nothing already written can be quietly rewritten by a later publish. An equal
// chain is NOT an extension; re-publishing an unchanged history is a no-op the caller can skip.
func (h *AddressHistoryRecord) Extends(prior *AddressHistoryRecord) bool {
	if prior == nil || len(prior.Chain) == 0 {
		return len(h.Chain) > 0
	}
	if len(h.Chain) <= len(prior.Chain) {
		return false
	}
	for i := range prior.Chain {
		// Compare on the entry's own signature: it covers every field, so two entries that agree
		// on it agree on everything, and a rewritten one cannot match.
		if !bytes.Equal(h.Chain[i].Signature, prior.Chain[i].Signature) {
			return false
		}
	}
	return true
}

// Terminal returns the last transition, or nil for an empty history.
func (h *AddressHistoryRecord) Terminal() *RotationEntry {
	if h == nil || len(h.Chain) == 0 {
		return nil
	}
	return &h.Chain[len(h.Chain)-1]
}

// RotatedFrom reports whether `pub` appears in this history as a key the address used to hold,
// and when it handed over.
//
// This is the question a reader brings here: their pinned key fell outside the capped window on
// the record, and they need to know whether it is part of this address's past or was never its
// key at all.
func (h *AddressHistoryRecord) RotatedFrom(pub ed25519.PublicKey) (time.Time, bool) {
	if h == nil || len(pub) == 0 {
		return time.Time{}, false
	}
	for i := range h.Chain {
		if bytes.Equal(h.Chain[i].RetiredEd25519Public, pub) {
			return h.Chain[i].RotatedAt, true
		}
	}
	return time.Time{}, false
}

// ToProto converts the history to its protobuf representation.
func (h *AddressHistoryRecord) ToProto() *dmcnpb.AddressHistoryRecord {
	pb := &dmcnpb.AddressHistoryRecord{Version: h.Version, Domain: h.Domain, Address: h.Address}
	for i := range h.Chain {
		pb.Chain = append(pb.Chain, h.Chain[i].ToProto())
	}
	return pb
}

// AddressHistoryRecordFromProto converts a protobuf history into its Go representation.
func AddressHistoryRecordFromProto(pb *dmcnpb.AddressHistoryRecord) (*AddressHistoryRecord, error) {
	if pb == nil {
		return nil, errors.New("identity: nil history record")
	}
	chain, err := rotationChainFromProto(pb.Chain)
	if err != nil {
		return nil, err
	}
	return &AddressHistoryRecord{Version: pb.Version, Domain: pb.Domain, Address: pb.Address, Chain: chain}, nil
}
