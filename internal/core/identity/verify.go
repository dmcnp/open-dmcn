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
)

var (
	// ErrRebindTombstoneRequired: the rule was evaluated and the rebind is NOT authorized.
	ErrRebindTombstoneRequired = errors.New("identity: re-binding an address requires a root-signed removal of the incumbent key")
	// ErrRebindUnverifiable: the rule could NOT be evaluated (no domain authority available), so
	// the caller must apply its own policy. Distinct from denial on purpose: a fleet node that
	// serves the domain should fail closed, while a standalone/dev node has no DAR to consult and
	// must not be bricked by that.
	ErrRebindUnverifiable = errors.New("identity: cannot evaluate re-binding without the domain authority record")
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
func AuthorizeRebind(prev, next *IdentityRecord, rm *AddressRemovalRecord, dar *DomainAuthorityRecord) (RebindArm, error) {
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
	if rm == nil {
		return "", ErrRebindTombstoneRequired
	}
	// Bind the tombstone to THIS address. Removed() matches on the key alone, so without this a
	// root-signed removal freeing a key at one address would be a transferable capability to
	// re-bind any other address that key happens to hold.
	if !strings.EqualFold(rm.Address, next.Address) {
		return "", fmt.Errorf("%w: removal record names %q, not %q", ErrRebindTombstoneRequired, rm.Address, next.Address)
	}
	if !strings.EqualFold(rm.Domain, dar.Domain) {
		return "", fmt.Errorf("%w: removal record domain %q is outside the authority for %q", ErrRebindTombstoneRequired, rm.Domain, dar.Domain)
	}
	// ROOT ONLY, deliberately — not RemovalSuppresses. An owner-signed retirement suppresses the
	// binding but must never authorise a different key to take the address, or a stolen key could
	// authorise its own replacement and key compromise would stop being recoverable. See
	// RemovalIsOwnerSigned.
	if !RemovalIsRootSigned(dar, rm) {
		return "", fmt.Errorf("%w: removal record is not signed by a domain root key", ErrRebindTombstoneRequired)
	}
	if _, ok := rm.Removed(prev.Ed25519Public); !ok {
		return "", fmt.Errorf("%w: the incumbent key is not tombstoned", ErrRebindTombstoneRequired)
	}
	return RebindRootTombstone, nil
}
