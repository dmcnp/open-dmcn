package bridge

import (
	"crypto/ed25519"
	"time"
)

// Classify determines the trust tier for an inbound legacy email based
// on its authentication results.
//
// Classification rules (evaluated in order):
//   - DKIM pass AND DMARC pass → TrustTierVerifiedLegacy
//   - DKIM fail, DMARC fail, OR SPF hard fail → TrustTierSuspicious
//   - Otherwise (missing/neutral checks, SPF softfail) → TrustTierUnverifiedLegacy
//
// The Verified check is evaluated first on purpose: a passing DMARC evaluation
// already implies an aligned SPF or DKIM pass, so a message that is DKIM- and
// DMARC-authenticated stays Verified even when SPF fails (common for forwarded
// mail). SPF is only consulted as a downgrade signal when the message is not
// otherwise authenticated. SPF softfail is treated as merely unverified, not
// suspicious. Hard rejects (DMARC p=reject failures) are handled separately by
// ShouldReject and never reach classification.
func Classify(result *AuthResult) BridgeTrustTier {
	if result.DKIM == DKIMPass && result.DMARC == DMARCPass {
		return TrustTierVerifiedLegacy
	}
	if result.DKIM == DKIMFail || result.DMARC == DMARCFail || result.SPF == SPFFail {
		return TrustTierSuspicious
	}
	return TrustTierUnverifiedLegacy
}

// ShouldReject reports whether an inbound message must be dropped outright rather
// than delivered with a trust tier. The bridge rejects only the unambiguous hard
// failure: a DMARC evaluation failure under a published p=reject policy (which
// also covers "SPF fail with no aligned DKIM under reject"). A bare invalid DKIM
// signature, an SPF softfail, or a DMARC failure under p=none/p=quarantine is
// delivered and surfaced as suspicious instead — the "drop on hard authentication
// failure" rule (SPEC.md §7) without over-blocking
// legitimate mail whose domain owner has not opted into enforcement.
func ShouldReject(result *AuthResult) bool {
	return result.DMARC == DMARCFail && result.DMARCPolicy == DMARCPolicyReject
}

// NewClassificationRecord constructs a BridgeClassificationRecord from the
// authentication result and trust tier. The record is unsigned; call Sign()
// before attaching to a message.
func NewClassificationRecord(
	bridgeAddr string,
	bridgePubKey ed25519.PublicKey,
	smtpFrom string,
	authResult *AuthResult,
	tier BridgeTrustTier,
) *BridgeClassificationRecord {
	return &BridgeClassificationRecord{
		BridgeAddress:   bridgeAddr,
		BridgePublicKey: bridgePubKey,
		SMTPFrom:        smtpFrom,
		SMTPSenderIP:    authResult.SenderIP,
		SPFResult:       authResult.SPF,
		DKIMResult:      authResult.DKIM,
		DMARCResult:     authResult.DMARC,
		ReputationScore: 0, // stubbed for PoC
		TrustTier:       tier,
		ClassifiedAt:    time.Now().UTC(),
	}
}
