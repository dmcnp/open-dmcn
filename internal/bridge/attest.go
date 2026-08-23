package bridge

import (
	"bytes"
	"crypto/ed25519"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// attest.go is how a recipient decides whether to believe a bridge's account of an inbound
// legacy email.
//
// A bridge is INFRASTRUCTURE, not a correspondent. It has no DMCN email address and no entry in
// anyone's directory; it is a peer whose domain's root key has signed a credential saying "this
// key may act as a bridge for this domain". Verifying an attestation is therefore entirely
// self-contained: the record carries that credential, the credential names the key that signed
// the record, and the credential is checked against the domain root a recipient already has to
// resolve the domain at all.
//
// That replaces an earlier model where the bridge held a `bridge@<domain>` mailbox and recipients
// resolved it to look up a `bridge_capability` flag. Giving a piece of infrastructure a mailbox
// invited it to be treated as a correspondent, made attestation verification depend on a live
// directory lookup, and meant a bridge had to be provisioned like a person before it could work.
// None of that bought anything the credential does not.

// AttestationVerdict is the outcome of verifying a bridge's classification record. A message is
// only safe to surface with its bridge-asserted trust tier when Verified is true.
type AttestationVerdict struct {
	// Verified is true when the record's signature is valid, it carries a root-signed `bridge`
	// credential, and that credential's subject is the key that signed the record. Only then
	// does TrustTier carry meaning.
	Verified bool
	// TrustTier is the bridge-asserted legacy-auth tier from the record — it describes the
	// LEGACY sender's SPF/DKIM/DMARC result, not the bridge. Only trustworthy when Verified.
	TrustTier BridgeTrustTier
	// Reason explains why verification failed (empty when Verified).
	Reason string
}

// ClassificationFromAttachments returns the bridge classification record carried by a message's
// attachments, or (nil, false) if none is present.
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

// ReceiptFromAttachments returns the bridge delivery receipt carried by a message's attachments,
// or (nil, false) if none is present.
func ReceiptFromAttachments(attachments []message.AttachmentRecord) (*BridgeDeliveryReceipt, bool) {
	for _, att := range attachments {
		if att.ContentType == ReceiptContentType {
			rec, err := UnmarshalDeliveryReceipt(att.Content)
			if err != nil {
				return nil, false
			}
			return rec, true
		}
	}
	return nil, false
}

// VerifyClassificationAttestation checks that a bridge's account of an inbound legacy email can be
// trusted, against the domain root key that anchors the bridge's domain.
//
// anchorPub is the root key from the bridge domain's authority record — the same key a recipient
// already checks every record on that domain against, and which they hold after resolving its
// `_dmcn` fingerprint. Passing the wrong domain's root simply fails: the credential names its
// issuer, and the check is exact.
func VerifyClassificationAttestation(rec *BridgeClassificationRecord, anchorPub ed25519.PublicKey) AttestationVerdict {
	if rec == nil {
		return AttestationVerdict{Reason: "no classification record"}
	}
	// 1. Internally consistent: signed by the key it carries.
	if err := rec.Verify(); err != nil {
		return AttestationVerdict{Reason: "invalid bridge signature"}
	}
	if v := verifyBridgeCredential(rec.BridgeCredential, rec.BridgePublicKey, anchorPub); v != "" {
		return AttestationVerdict{Reason: v}
	}
	return AttestationVerdict{Verified: true, TrustTier: rec.TrustTier}
}

// DeliveryReceiptVerdict is the outcome of verifying a bridge delivery receipt — the sender's
// confirmation that their outbound-to-legacy message did or did not arrive.
type DeliveryReceiptVerdict struct {
	// Verified is true when the receipt is signed by a key carrying a root-signed `bridge`
	// credential. Only then do Success and ErrorDetail mean anything.
	Verified bool
	// Success is the bridge's claim about delivery. Only trustworthy when Verified.
	Success bool
	// Reason explains why verification failed (empty when Verified).
	Reason string
}

// VerifyDeliveryReceipt checks a delivery receipt the same way a classification record is checked.
// Without it a receipt is an unauthenticated claim that mail was (or was not) delivered, which is
// worth exactly nothing to the sender relying on it.
func VerifyDeliveryReceipt(rec *BridgeDeliveryReceipt, anchorPub ed25519.PublicKey) DeliveryReceiptVerdict {
	if rec == nil {
		return DeliveryReceiptVerdict{Reason: "no delivery receipt"}
	}
	// Unlike a classification record, the receipt carries no separate signer key — the
	// credential's subject IS the claimed signer, so establish the credential first and then
	// check the signature against the key it names. Doing it in this order matters: verifying
	// the signature against a key taken from the same unverified record would be circular.
	if v := verifyBridgeCredential(rec.BridgeCredential, credSubject(rec.BridgeCredential), anchorPub); v != "" {
		return DeliveryReceiptVerdict{Reason: v}
	}
	if err := rec.Verify(rec.BridgeCredential.Subject); err != nil {
		return DeliveryReceiptVerdict{Reason: "invalid bridge signature"}
	}
	return DeliveryReceiptVerdict{Verified: true, Success: rec.Success}
}

// verifyBridgeCredential is the shared check behind both verdicts, returning a reason string on
// failure and "" on success.
//
// The subject==signer step is the one that carries the weight. A valid `bridge` credential proves
// some key is a bridge for the domain; only binding it to the key that signed THIS record proves
// anything about this record. Without it, anyone could staple a real bridge's credential onto
// their own signed attestation.
func verifyBridgeCredential(cred *identity.Credential, signer, anchorPub ed25519.PublicKey) string {
	if cred == nil {
		return "no bridge credential"
	}
	if err := identity.VerifyFleetCredential(cred, anchorPub, time.Now()); err != nil {
		return "bridge credential invalid: " + err.Error()
	}
	if !cred.HasRole(identity.RoleBridge) {
		return "credential does not carry the bridge role"
	}
	if len(signer) == 0 || !bytes.Equal(cred.Subject, signer) {
		return "bridge credential subject does not match the signing key"
	}
	return ""
}

// credSubject is the credential's subject, or nil when there is no credential — so the
// subject==signer check degrades to "no credential" rather than panicking.
func credSubject(c *identity.Credential) ed25519.PublicKey {
	if c == nil {
		return nil
	}
	return c.Subject
}
