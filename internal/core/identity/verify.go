package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
)

// addressDomain returns the domain portion of a local@domain address (mirrors
// domainverify.DomainOf without importing that package).
func addressDomain(address string) string {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// VerifyManagedRecord verifies an IdentityRecord's self-signature and its address/routing
// credentials against a SUPPLIED DomainAuthorityRecord (+ optional blocklist and removal
// tombstone), returning the effective verification tier. It is PURE — no network I/O — so it
// verifies a fleet-served record from a fleet-served DAR with no lookup of its own.
//
// The CALLER is responsible for the two anchors this function cannot check locally:
//   - the DAR is anchored to DNS (its Fingerprint() == the domain's _dmcn TXT), and
//   - any fleet deferral is confirmed (DNS fleet= == dar.FleetDomain).
//
// It mirrors the reader-side trust rules of registry.VerifyManagedIdentity: an uncredentialed
// record returns its self-claimed tier; a credentialed record must match + chain to the DAR (and
// not be tombstoned) to reach TierDomainDNS.
func VerifyManagedRecord(rec *IdentityRecord, dar *DomainAuthorityRecord, blocks *CredentialBlockList, removal *AddressRemovalRecord, now time.Time) (VerificationTier, error) {
	if rec == nil || dar == nil {
		return TierUnverified, errors.New("identity: nil record or DAR")
	}
	if err := rec.Verify(); err != nil {
		return TierUnverified, fmt.Errorf("identity: self-signature: %w", err)
	}
	domain := addressDomain(rec.Address)
	if domain == "" || !strings.EqualFold(domain, dar.Domain) {
		return TierUnverified, fmt.Errorf("identity: record domain %q != DAR domain %q", domain, dar.Domain)
	}

	// Operator routing credential (RelayHints is operator-owned, excluded from the self-signature).
	if rec.HasRoutingCredential() {
		rc := rec.RoutingCredential
		if rc.Domain != dar.Domain || rc.Address != rec.Address || !rc.HasRole(RoleRouting) || !bytes.Equal(rc.Subject, rec.Ed25519Public) {
			return TierUnverified, errors.New("identity: routing credential does not match record")
		}
		if !relayHintsEqual(rec.RelayHints, rc.RelayHints) {
			return TierUnverified, errors.New("identity: relay hints do not match routing credential")
		}
		if err := VerifyCredential(rc, dar, blocks, now); err != nil {
			return TierUnverified, fmt.Errorf("identity: routing credential: %w", err)
		}
	}

	// Domain address credential (the domain's attestation of the address↔key binding).
	if !rec.HasAddressCredential() {
		return rec.VerificationTier, nil
	}
	cred := rec.AddressCredential
	if cred.Domain != dar.Domain || cred.Address != rec.Address || !cred.HasRole(RoleAddress) || !bytes.Equal(cred.Subject, rec.Ed25519Public) {
		return TierUnverified, errors.New("identity: address credential does not match record")
	}
	if err := VerifyCredential(cred, dar, blocks, now); err != nil {
		return TierUnverified, fmt.Errorf("identity: address credential: %w", err)
	}
	// A removal tombstone still invalidates the binding. Either signer suppresses: the domain
	// root (the operator retiring or rotating an address) or the address's OWN key (the holder
	// retiring it themselves). Suppression is the half of a tombstone that is safe to delegate —
	// see RemovalIsOwnerSigned for the half that is not.
	if removal != nil && RemovalSuppresses(rec, dar, removal) {
		if _, removed := removal.Removed(rec.Ed25519Public); removed {
			return TierUnverified, errors.New("identity: binding removed")
		}
	}
	return TierDomainDNS, nil
}

// relayHintsEqual reports whether two ordered relay-hint lists are identical.
func relayHintsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RemovalIsRootSigned reports whether an AddressRemovalRecord is signed by a root key the DAR
// vouches for (the current key effective at the removal's timestamp, or any key in the timeline).
// A nil DAR or record is NOT root-signed: callers that could not resolve the domain authority must
// not be able to mistake "cannot verify" for "verified".
func RemovalIsRootSigned(dar *DomainAuthorityRecord, rm *AddressRemovalRecord) bool {
	if dar == nil || rm == nil {
		return false
	}
	if pub, ok := dar.RootKeyAt(rm.CreatedAt); ok && rm.Verify(pub) == nil {
		return true
	}
	for _, pub := range darRootKeys(dar) {
		if rm.Verify(pub) == nil {
			return true
		}
	}
	return false
}

// RemovalIsOwnerSigned reports whether an AddressRemovalRecord is signed by the key the record
// itself is bound to — the address retiring ITSELF. The holder of an address can always stop
// being reachable at it, and needs no operator to do so: the browser already holds the key.
//
// An owner-signed removal SUPPRESSES and NOTHING ELSE. It must never reach AuthorizeRebind,
// because a tombstone does two jobs and only the first is safe to delegate:
//
//  1. suppress the binding — the address stops resolving, stops being served, stops FETCHing;
//  2. authorise a DIFFERENT key to take the address over (RebindRootTombstone).
//
// Root-only on (2) is what makes a stolen key survivable: an attacker who holds the key can read
// mail, but cannot take the address permanently, because rebinding needs the offline root. If a
// key could authorise its own replacement, key compromise would stop being recoverable and become
// a permanent takeover. So the rebind gate keeps asking RemovalIsRootSigned, and only the
// suppression paths ask this.
//
// The two are told apart by WHICH key verifies the existing signature, so no field distinguishes
// them on the wire and the signed bytes are unchanged.
func RemovalIsOwnerSigned(rec *IdentityRecord, rm *AddressRemovalRecord) bool {
	if rec == nil || rm == nil || len(rec.Ed25519Public) == 0 {
		return false
	}
	// Bind the tombstone to THIS address, exactly as AuthorizeRebind does: Removed() matches on
	// the key alone, so without this a self-retirement at one address would suppress every other
	// address the same key holds.
	if !strings.EqualFold(rm.Address, rec.Address) {
		return false
	}
	return rm.Verify(rec.Ed25519Public) == nil
}

// RemovalSuppresses reports whether a removal record may invalidate this record's binding —
// signed either by a domain root key or by the address's own key. This is the read-side rule;
// the rebind gate deliberately asks the narrower RemovalIsRootSigned instead.
func RemovalSuppresses(rec *IdentityRecord, dar *DomainAuthorityRecord, rm *AddressRemovalRecord) bool {
	return RemovalIsRootSigned(dar, rm) || RemovalIsOwnerSigned(rec, rm)
}

// BlocklistIsRootSigned reports whether a CredentialBlockList is signed by a root key the DAR
// vouches for. A reader MUST check this before honoring a blocklist — otherwise an untrusted
// carrier (a hostile fleet) could censor a valid credential with a forged blocklist.
func BlocklistIsRootSigned(dar *DomainAuthorityRecord, bl *CredentialBlockList) bool {
	if dar == nil || bl == nil {
		return false
	}
	for _, pub := range darRootKeys(dar) {
		if bl.Verify(pub) == nil {
			return true
		}
	}
	return false
}

func darRootKeys(dar *DomainAuthorityRecord) []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(dar.SupersededKeys)+1)
	keys = append(keys, dar.AuthorityEd25519)
	for _, k := range dar.SupersededKeys {
		keys = append(keys, k.Ed25519Public)
	}
	return keys
}

// --- Address re-binding ------------------------------------------------------------------------

// RebindArm names the rule that authorized an address↔key binding. Returned by AuthorizeRebind so
// callers can log WHY a write was allowed, and so a new arm can be added without changing the
// signature (a user-held recovery key is the planned next one).
type RebindArm string

const (
	// RebindGenesis: no incumbent record — a first binding.
	RebindGenesis RebindArm = "genesis"
	// RebindSameKey: the owner key is unchanged — a republish, not a rebind. This is the arm
	// every operator flow takes (rebalance, drain, approve, credential re-issue).
	RebindSameKey RebindArm = "same-key"
	// RebindRootTombstone: the domain root tombstoned the incumbent key, freeing the address.
	RebindRootTombstone RebindArm = "root-tombstone"
	// RebindOwnerRotation: the owner re-keyed their own address. The incoming record carries a
	// rotation chain whose terminal entry is signed by the key it displaces (or that record's
	// recovery key) and attested by an enrolled device, so continuity of control is proven
	// without the operator. Only on domains whose DAR opts in.
	RebindOwnerRotation RebindArm = "owner-rotation"
)

var (
	// ErrRebindTombstoneRequired: the rule was evaluated and the rebind is NOT authorized.
	ErrRebindTombstoneRequired = errors.New("identity: re-binding an address requires a root-signed removal of the incumbent key")
	// ErrRebindUnverifiable: the rule could NOT be evaluated (no domain authority available), so
	// the caller must apply its own policy. Distinct from denial on purpose: a fleet node that
	// serves the domain should fail closed, while a standalone/dev node has no DAR to consult and
	// must not be bricked by that.
	ErrRebindUnverifiable = errors.New("identity: cannot evaluate re-binding without the domain authority record")
	// ErrRebindRotationNotAllowed: the incoming record carries a rotation chain, but this domain
	// does not permit owner-authorized re-keying. Distinct from a malformed chain so an operator
	// can tell "your domain has not enabled this" from "this chain does not verify".
	ErrRebindRotationNotAllowed = errors.New("identity: this domain does not permit owner-authorized key rotation")
)

// AuthorizeRebind decides whether `next` may replace `prev` as the record for an address, and
// returns the arm that authorized it.
//
// This is the rule that makes the AddressRemovalRecord contract real: "Only the domain root can
// publish one, so only root can free an address for re-binding." An AddressCredential is an
// ordinary role-bearing leaf, so any DAR-enrolled issuer holding the `address` grant can attest
// ANY address↔key binding on its domain. That is correct for attesting a binding and wrong for
// CHANGING one — the missing rule is state-relative, so it lives here and at the store rather
// than in the capability calculus.
//
// prev == nil means the caller holds no incumbent record. Note the boundary this implies: the
// check is state-relative, so a node with no prior record accepts anything as a genesis binding.
// It defeats theft of an online issuing key; it does not defeat an operator who controls both
// issuance and every serving node.
func AuthorizeRebind(prev, next *IdentityRecord, rm *AddressRemovalRecord, dar *DomainAuthorityRecord, now time.Time) (RebindArm, error) {
	if next == nil {
		return "", errors.New("identity: no record to authorize")
	}
	if prev == nil {
		return RebindGenesis, nil
	}
	if bytes.Equal(prev.Ed25519Public, next.Ed25519Public) {
		return RebindSameKey, nil
	}
	if dar == nil {
		return "", ErrRebindUnverifiable
	}
	// The OPERATOR arm is evaluated first, so a root tombstone always outranks anything the
	// owner can produce. An offboarded key whose binding the root freed must not be able to
	// argue its way back by presenting a chain.
	missing := "the incumbent key is not tombstoned"
	if rm != nil {
		freed, why := rebindTombstoneFrees(prev, next, rm, dar)
		if freed {
			return RebindRootTombstone, nil
		}
		missing = why
	}
	// Then the OWNER arm: re-keying with no operator involved, on domains that opted in.
	if len(next.RotationChain) > 0 {
		return authorizeOwnerRotation(prev, next, rm, dar, now)
	}
	return "", fmt.Errorf("%w: %s", ErrRebindTombstoneRequired, missing)
}

// rebindTombstoneFrees reports whether a root-signed removal has freed this address for any key,
// and when it has not, which condition was missing.
//
// The reason is carried out rather than discarded because this arm is where an operator lands
// when a re-provision is refused: the four ways to fail are four different things to go and fix,
// and "requires a root-signed removal" on its own names none of them.
func rebindTombstoneFrees(prev, next *IdentityRecord, rm *AddressRemovalRecord, dar *DomainAuthorityRecord) (bool, string) {
	// Bind the tombstone to THIS address. Removed() matches on the key alone, so without this a
	// root-signed removal freeing a key at one address would be a transferable capability to
	// re-bind any other address that key happens to hold.
	if !strings.EqualFold(rm.Address, next.Address) {
		return false, fmt.Sprintf("removal record names %q, not %q", rm.Address, next.Address)
	}
	if !strings.EqualFold(rm.Domain, dar.Domain) {
		return false, fmt.Sprintf("removal record domain %q is outside the authority for %q", rm.Domain, dar.Domain)
	}
	// ROOT ONLY, deliberately — not RemovalSuppresses. An owner-signed retirement suppresses the
	// binding but must never authorise a different key to take the address, or a stolen key could
	// authorise its own replacement and key compromise would stop being recoverable. See
	// RemovalIsOwnerSigned.
	if !RemovalIsRootSigned(dar, rm) {
		return false, "removal record is not signed by a domain root key"
	}
	if _, ok := rm.Removed(prev.Ed25519Public); !ok {
		return false, "the incumbent key is not tombstoned"
	}
	return true, ""
}

// authorizeOwnerRotation decides whether `next` may displace `prev` on the strength of its own
// rotation chain — the owner re-keying with no operator involved.
//
// What it establishes, in order: the domain permits this at all; the chain holds together and
// belongs to this record; its terminal transition is anchored on exactly the record being
// displaced; the key giving the address up genuinely consented; an enrolled device of sufficient
// tenure asked for it; and the key being rotated INTO is not one the root has tombstoned.
func authorizeOwnerRotation(prev, next *IdentityRecord, rm *AddressRemovalRecord, dar *DomainAuthorityRecord, now time.Time) (RebindArm, error) {
	// Policy first, so a domain that has not opted in gets a clear answer rather than a
	// cryptographic one. (The product fork additionally refuses on admin-key-custody domains,
	// a deployment posture this core has no concept of.)
	if !dar.AllowKeyRotation() {
		return "", ErrRebindRotationNotAllowed
	}
	if err := VerifyRotationChain(next); err != nil {
		return "", err
	}

	last := &next.RotationChain[len(next.RotationChain)-1]
	// Anchor the terminal transition on the record actually being displaced. Without this a
	// genuine chain ending in this key could be carried by a record displacing some OTHER
	// incumbent — a transferable capability rather than one address's history.
	if !bytes.Equal(last.RetiredEd25519Public, prev.Ed25519Public) || last.RetiredX25519Public != prev.X25519Public {
		return "", fmt.Errorf("%w: the last transition retires a key other than the one currently bound", ErrRebindTombstoneRequired)
	}
	// The consent must come from the incumbent itself, or from the recovery key IT published.
	// A recovery key named by the incoming record would let an attacker supply their own.
	if !bytes.Equal(last.AuthorizingEd25519Public, prev.Ed25519Public) &&
		!bytes.Equal(last.AuthorizingEd25519Public, prev.RecoveryEd25519Public) {
		return "", fmt.Errorf("%w: the transition was authorized by a key the displaced record never published", ErrRebindTombstoneRequired)
	}
	if next.Revision <= prev.Revision {
		return "", fmt.Errorf("%w: revision %d does not advance past %d", ErrRebindTombstoneRequired, next.Revision, prev.Revision)
	}
	if err := authorizeRotationDevice(last, dar, now); err != nil {
		return "", err
	}
	// A key the root has tombstoned must not be rotated INTO, or an offboarded key could be
	// brought back by a rotation the owner signs on its behalf.
	if rm != nil && RemovalIsRootSigned(dar, rm) && strings.EqualFold(rm.Address, next.Address) {
		if _, tombstoned := rm.Removed(next.Ed25519Public); tombstoned {
			return "", fmt.Errorf("%w: the incoming key is tombstoned on this address", ErrRebindTombstoneRequired)
		}
	}
	return RebindOwnerRotation, nil
}

// rotationSkew tolerates small clock differences when judging whether a rotation is dated ahead
// of the node checking it, matching credSkew and permitSkew.
const rotationSkew = 2 * time.Minute

// authorizeRotationDevice checks that an enrolled device of sufficient tenure asked for this
// transition.
//
// This is what makes a stolen ACCOUNT key insufficient. Device keys are generated on their
// device and held nowhere else, so a thief working from a backup export or a pairing payload has
// none — and the tenure minimum means that even enrolling one buys them only a wait, during
// which the device appears in the owner's list.
//
// Verified against the rotation's OWN time rather than now: a credential valid when the
// transition was made stays valid for it, which is what lets history remain checkable.
func authorizeRotationDevice(e *RotationEntry, dar *DomainAuthorityRecord, now time.Time) error {
	if e.DeviceCredential == nil {
		return fmt.Errorf("%w: no enrolled device attested this transition", ErrRebindTombstoneRequired)
	}
	if !e.DeviceCredential.HasRole(RoleDevice) {
		return fmt.Errorf("%w: the attesting credential is not a device credential", ErrRebindTombstoneRequired)
	}
	// Bind the device to THIS address, or a device enrolled for one account could authorize a
	// rotation on another.
	if !strings.EqualFold(e.DeviceCredential.Address, e.Address) {
		return fmt.Errorf("%w: the attesting device is enrolled for %q, not %q", ErrRebindTombstoneRequired, e.DeviceCredential.Address, e.Address)
	}
	if err := VerifyCredential(e.DeviceCredential, dar, nil, e.RotatedAt); err != nil {
		return fmt.Errorf("%w: the attesting device credential does not verify: %v", ErrRebindTombstoneRequired, err)
	}
	// The rotation may not be dated ahead of this node's clock.
	//
	// Both ends of the tenure measurement below are chosen by whoever makes the entry: the
	// credential's issue date and the rotation's own. Nothing in the chain bounds either against
	// the outside world — entries are checked against each OTHER — so a thief who enrolled a
	// device today and dated the transition a year out would satisfy any minimum a domain can
	// set, and the tenure rule would be decorative. The node's clock is the outside reference,
	// with the tolerance the credential windows already use.
	if ahead := e.RotatedAt.Sub(now); ahead > rotationSkew {
		return fmt.Errorf("%w: the transition is dated %s ahead of this node's clock",
			ErrRebindTombstoneRequired, ahead.Round(time.Second))
	}
	// Tenure is measured to the rotation, not to now, so a slow-propagating record is judged by
	// when it was made — and, with the bound above, cannot be stretched by claiming a later one.
	if age := e.RotatedAt.Sub(e.DeviceCredential.IssuedAt); age < dar.RotationMinDeviceAge() {
		return fmt.Errorf("%w: the attesting device had been enrolled %s, short of the %s this domain requires",
			ErrRebindTombstoneRequired, age.Round(time.Hour), dar.RotationMinDeviceAge())
	}
	return nil
}
