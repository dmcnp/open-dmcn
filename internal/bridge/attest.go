package bridge

import (
	"bytes"
	"fmt"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// BridgeTrust is the registry-resolved trust state of a classification record's
// signer, as the caller obtained it. Callers populate it from
// registry.Lookup + registry.VerifyManagedIdentity:
//
//	rec, _ := reg.Lookup(ctx, classification.BridgeAddress)
//	tier, err := reg.VerifyManagedIdentity(ctx, rec)
//	trust := BridgeTrust{Record: rec, VerifiedTier: tier, VerifyErr: err}
//
// VerifyManagedIdentity already folds in domain-anchoring (the DAR/DNS chain,
// gap #7) and revocation (an AddressRemovalRecord tombstoning the binding makes
// it return a non-nil error, gap #9), so a single call carries both signals.
type BridgeTrust struct {
	// Record is the signer's identity record from the registry; nil if the
	// bridge address could not be resolved.
	Record *identity.IdentityRecord
	// VerifiedTier is the tier returned by VerifyManagedIdentity (the
	// cryptographically verified tier, not the self-claimed field).
	VerifiedTier identity.VerificationTier
	// VerifyErr is the error from VerifyManagedIdentity. A non-nil value means
	// the bridge claimed a domain countersignature that failed to verify — e.g.
	// its binding was tombstoned (revoked) or the countersigner is no longer
	// authorized — and the attestation is always rejected, regardless of minTier.
	VerifyErr error
}

// AttestationVerdict is the outcome of verifying a bridge's classification
// record against the identity registry. A message is only safe to surface with
// its bridge-asserted trust tier when Verified is true.
type AttestationVerdict struct {
	// Verified is true when the record's signature is valid, its signer is a
	// registered bridge (BridgeCapability) whose registry key matches the key in
	// the record, the signer's identity is not revoked, and its verified tier
	// meets the required minimum. Only then does TrustTier carry meaning.
	Verified bool
	// TrustTier is the bridge-asserted legacy-auth tier from the record. It is
	// only trustworthy when Verified is true.
	TrustTier BridgeTrustTier
	// BridgeTier is the bridge identity's cryptographically verified tier.
	BridgeTier identity.VerificationTier
	// DomainAnchored is true when the bridge identity is countersigned by its
	// domain authority (verified tier >= TierDomainDNS).
	DomainAnchored bool
	// Reason explains why verification failed (empty when Verified).
	Reason string
}

// ClassificationFromAttachments returns the bridge classification record carried
// by a message's attachments, or (nil, false) if none is present.
func ClassificationFromAttachments(attachments []message.AttachmentRecord) (*BridgeClassificationRecord, bool) {
	for _, att := range attachments {
		if att.ContentType == ClassificationContentType {
			rec, err := UnmarshalClassificationRecord(att.Content)
			if err != nil {
				return nil, false
			}
			return rec, true
		}
	}
	return nil, false
}

// VerifyClassificationAttestation checks that a bridge classification record can
// be trusted: its signature must be valid; its signer must be a registered bridge
// whose registry key matches the key embedded in the record; the signer's
// identity must not be revoked; and its verified tier must meet minTier.
//
// trust carries the signer's registry state (see BridgeTrust). minTier is the
// policy minimum verified tier — pass identity.TierUnverified for no anchoring
// requirement (the lenient, reader-side-upgrade default), or identity.TierDomainDNS
// to require the bridge be domain-anchored. Revocation (trust.VerifyErr != nil)
// is always rejected, independent of minTier.
//
// This mirrors the client-side check the web app performs, so the same trust
// decision is available to non-web clients.
func VerifyClassificationAttestation(rec *BridgeClassificationRecord, trust BridgeTrust, minTier identity.VerificationTier) AttestationVerdict {
	if rec == nil {
		return AttestationVerdict{Reason: "no classification record"}
	}
	// 1. The record must be internally consistent: signed by the key it carries.
	if err := rec.Verify(); err != nil {
		return AttestationVerdict{Reason: "invalid bridge signature"}
	}
	// 2. The signer must be resolvable in the registry.
	if trust.Record == nil {
		return AttestationVerdict{Reason: "bridge identity not found in registry"}
	}
	// 3. The signer must actually be a bridge.
	if !trust.Record.BridgeCapability {
		return AttestationVerdict{Reason: "signer is not a registered bridge", BridgeTier: trust.VerifiedTier}
	}
	// 4. The record's key must match the bridge's registered key — otherwise a
	// valid self-signature proves nothing about the named bridge.
	if !bytes.Equal(trust.Record.Ed25519Public, rec.BridgePublicKey) {
		return AttestationVerdict{Reason: "bridge key does not match registry", BridgeTier: trust.VerifiedTier}
	}
	// 5. Revocation / invalid anchoring: the bridge claimed a domain
	// countersignature that failed to verify (binding tombstoned, countersigner
	// no longer authorized, DAR/DNS chain broken). Always reject — a revoked
	// bridge must never be trusted, whatever the minTier policy.
	if trust.VerifyErr != nil {
		return AttestationVerdict{Reason: "bridge identity revoked or unverifiable: " + trust.VerifyErr.Error(), BridgeTier: trust.VerifiedTier}
	}
	// 6. Anchoring policy: require at least the configured verified tier.
	if trust.VerifiedTier < minTier {
		return AttestationVerdict{
			Reason:     fmt.Sprintf("bridge not anchored to its domain (verified tier %d, require %d)", trust.VerifiedTier, minTier),
			BridgeTier: trust.VerifiedTier,
		}
	}
	return AttestationVerdict{
		Verified:       true,
		TrustTier:      rec.TrustTier,
		BridgeTier:     trust.VerifiedTier,
		DomainAnchored: trust.VerifiedTier >= identity.TierDomainDNS,
	}
}
