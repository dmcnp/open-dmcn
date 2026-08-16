package bridge_test

import (
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// signedClassification builds a classification record signed by bridgeKP.
func signedClassification(t *testing.T, bridgeKP *identity.IdentityKeyPair, tier bridge.BridgeTrustTier) *bridge.BridgeClassificationRecord {
	t.Helper()
	rec := bridge.NewClassificationRecord(tBridgeAddr, bridgeKP.Ed25519Public, "ext@gmail.com",
		&bridge.AuthResult{SPF: bridge.SPFPass, DKIM: bridge.DKIMPass, DMARC: bridge.DMARCPass}, tier)
	if err := rec.Sign(bridgeKP.Ed25519Private); err != nil {
		t.Fatalf("sign classification: %v", err)
	}
	return rec
}

// bridgeRecord builds a registry identity record for the bridge.
func bridgeRecord(addr string, kp *identity.IdentityKeyPair, capable bool, tier identity.VerificationTier) *identity.IdentityRecord {
	return &identity.IdentityRecord{
		Address:          addr,
		Ed25519Public:    kp.Ed25519Public,
		X25519Public:     kp.X25519Public,
		VerificationTier: tier,
		BridgeCapability: capable,
	}
}

func TestVerifyClassificationAttestation(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	otherKP := mustKeyPair(t)
	rec := signedClassification(t, bridgeKP, bridge.TrustTierVerifiedLegacy)
	const noMin = identity.TierUnverified

	t.Run("valid anchored", func(t *testing.T) {
		v := bridge.VerifyClassificationAttestation(rec, trustFor(tBridgeAddr, bridgeKP, true, identity.TierDomainDNS), noMin)
		if !v.Verified {
			t.Fatalf("expected verified, reason=%q", v.Reason)
		}
		if v.TrustTier != bridge.TrustTierVerifiedLegacy {
			t.Fatalf("trust tier = %d", v.TrustTier)
		}
		if v.BridgeTier != identity.TierDomainDNS || !v.DomainAnchored {
			t.Fatalf("bridge tier = %d anchored=%v", v.BridgeTier, v.DomainAnchored)
		}
	})

	t.Run("unanchored allowed under lenient policy", func(t *testing.T) {
		v := bridge.VerifyClassificationAttestation(rec, trustFor(tBridgeAddr, bridgeKP, true, identity.TierUnverified), noMin)
		if !v.Verified {
			t.Fatalf("unanchored bridge should verify under lenient policy, reason=%q", v.Reason)
		}
		if v.DomainAnchored {
			t.Fatal("tier-0 bridge must not be reported as domain-anchored")
		}
	})

	t.Run("unanchored rejected when anchoring required", func(t *testing.T) {
		v := bridge.VerifyClassificationAttestation(rec, trustFor(tBridgeAddr, bridgeKP, true, identity.TierUnverified), identity.TierDomainDNS)
		if v.Verified {
			t.Fatal("unanchored bridge must be rejected when minTier=TierDomainDNS")
		}
	})

	t.Run("revoked always rejected even under lenient policy", func(t *testing.T) {
		trust := bridge.BridgeTrust{
			Record:       bridgeRecord(tBridgeAddr, bridgeKP, true, identity.TierUnverified),
			VerifiedTier: identity.TierUnverified,
			VerifyErr:    errors.New("registry: binding removed by domain"),
		}
		if v := bridge.VerifyClassificationAttestation(rec, trust, noMin); v.Verified {
			t.Fatal("a revoked/unverifiable bridge must never verify")
		}
	})

	t.Run("nil record", func(t *testing.T) {
		if v := bridge.VerifyClassificationAttestation(nil, trustFor(tBridgeAddr, bridgeKP, true, identity.TierDomainDNS), noMin); v.Verified {
			t.Fatal("nil record must not verify")
		}
	})

	t.Run("bridge not in registry", func(t *testing.T) {
		if v := bridge.VerifyClassificationAttestation(rec, bridge.BridgeTrust{}, noMin); v.Verified {
			t.Fatal("unresolved bridge must not verify")
		}
	})

	t.Run("not a bridge", func(t *testing.T) {
		v := bridge.VerifyClassificationAttestation(rec, trustFor(tBridgeAddr, bridgeKP, false, identity.TierDomainDNS), noMin)
		if v.Verified {
			t.Fatal("a non-BridgeCapability signer must not verify")
		}
	})

	t.Run("key mismatch", func(t *testing.T) {
		v := bridge.VerifyClassificationAttestation(rec, trustFor(tBridgeAddr, otherKP, true, identity.TierDomainDNS), noMin)
		if v.Verified {
			t.Fatal("key mismatch must not verify")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := *rec
		bad.TrustTier = bridge.TrustTierSuspicious // changes signed bytes, sig no longer valid
		v := bridge.VerifyClassificationAttestation(&bad, trustFor(tBridgeAddr, bridgeKP, true, identity.TierDomainDNS), noMin)
		if v.Verified {
			t.Fatal("tampered record must not verify")
		}
	})
}

// trustFor builds a BridgeTrust for a bridge resolved at the given tier (no error).
func trustFor(addr string, kp *identity.IdentityKeyPair, capable bool, tier identity.VerificationTier) bridge.BridgeTrust {
	return bridge.BridgeTrust{Record: bridgeRecord(addr, kp, capable, tier), VerifiedTier: tier}
}

func TestClassificationFromAttachments(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	rec := signedClassification(t, bridgeKP, bridge.TrustTierVerifiedLegacy)
	raw, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	atts := []message.AttachmentRecord{
		{ContentType: "text/plain", Content: []byte("hi")},
		{ContentType: bridge.ClassificationContentType, Content: raw},
	}
	got, ok := bridge.ClassificationFromAttachments(atts)
	if !ok {
		t.Fatal("expected to find a classification attachment")
	}
	if got.BridgeAddress != tBridgeAddr {
		t.Fatalf("bridge address = %q", got.BridgeAddress)
	}

	if _, ok := bridge.ClassificationFromAttachments(atts[:1]); ok {
		t.Fatal("must not find a classification attachment when absent")
	}
}
