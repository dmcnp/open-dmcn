package bridge_test

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// attest_test.go covers the one question a recipient asks about bridged mail: should I believe
// this bridge's account of who sent it?
//
// The answer is entirely self-contained — the classification record carries a credential signed by
// the bridge domain's root, and that credential names the key that signed the record. There is no
// directory lookup and no bridge mailbox involved, which is why these tests need neither.

const attestDomain = "mesh.example"

func mustKP(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// issueBridgeCred signs a `bridge` credential for subject, as `dmcndcli bridge issue` does.
func issueBridgeCred(t *testing.T, root *identity.IdentityKeyPair, subject ed25519.PublicKey, roles ...string) *identity.Credential {
	t.Helper()
	if len(roles) == 0 {
		roles = []string{identity.RoleBridge}
	}
	cred := &identity.Credential{
		Version:  1,
		Subject:  subject,
		Domain:   attestDomain,
		Roles:    roles,
		IssuedAt: time.Now().UTC(),
	}
	if err := cred.Sign(root); err != nil {
		t.Fatalf("sign credential: %v", err)
	}
	return cred
}

// signedClassification builds a classification record signed by bridgeKP and carrying cred.
func signedClassification(t *testing.T, bridgeKP *identity.IdentityKeyPair, cred *identity.Credential) *bridge.BridgeClassificationRecord {
	t.Helper()
	rec := bridge.NewClassificationRecord(
		"12D3KooWFakePeerID", bridgeKP.Ed25519Public, "sender@legacy.example",
		&bridge.AuthResult{SPF: bridge.SPFPass, DKIM: bridge.DKIMPass, DMARC: bridge.DMARCPass},
		bridge.TrustTierVerifiedLegacy,
	)
	rec.BridgeCredential = cred
	if err := rec.Sign(bridgeKP.Ed25519Private); err != nil {
		t.Fatalf("sign classification: %v", err)
	}
	return rec
}

// TestAttestationAcceptsACredentialledBridge is the happy path: a bridge the domain root
// authorised, signing its own verdict.
func TestAttestationAcceptsACredentialledBridge(t *testing.T) {
	root, bridgeKP := mustKP(t), mustKP(t)
	rec := signedClassification(t, bridgeKP, issueBridgeCred(t, root, bridgeKP.Ed25519Public))

	v := bridge.VerifyClassificationAttestation(rec, root.Ed25519Public)
	if !v.Verified {
		t.Fatalf("a properly credentialled bridge was rejected: %s", v.Reason)
	}
	if v.TrustTier != bridge.TrustTierVerifiedLegacy {
		t.Errorf("trust tier = %v, want verified-legacy", v.TrustTier)
	}
}

// TestAttestationNeedsACredential pins that a bare signature proves nothing. Anyone can generate a
// keypair and sign a record claiming a legacy sender passed DMARC; the credential is the only
// thing that makes it an assertion by a bridge rather than by a stranger.
func TestAttestationNeedsACredential(t *testing.T) {
	root, bridgeKP := mustKP(t), mustKP(t)
	rec := signedClassification(t, bridgeKP, nil)

	v := bridge.VerifyClassificationAttestation(rec, root.Ed25519Public)
	if v.Verified {
		t.Fatal("a classification record with no credential was trusted")
	}
	if !strings.Contains(v.Reason, "credential") {
		t.Errorf("unhelpful reason: %s", v.Reason)
	}
}

// TestAttestationRejectsAStolenCredential is the substitution attack the subject==signer check
// exists for. A real bridge's credential is public — it travels in every message it signs — so an
// attacker can copy one. Stapling it to their own signed record must not work.
func TestAttestationRejectsAStolenCredential(t *testing.T) {
	root, realBridge, attacker := mustKP(t), mustKP(t), mustKP(t)
	stolen := issueBridgeCred(t, root, realBridge.Ed25519Public)

	// The attacker signs their own verdict, but attaches the real bridge's credential.
	rec := signedClassification(t, attacker, stolen)

	v := bridge.VerifyClassificationAttestation(rec, root.Ed25519Public)
	if v.Verified {
		t.Fatal("a record signed by one key but carrying another key's credential was trusted")
	}
	if !strings.Contains(v.Reason, "subject") {
		t.Errorf("reason does not point at the subject mismatch: %s", v.Reason)
	}
}

// TestAttestationRejectsAnotherDomainsRoot keeps the anchor exact. A credential signed by some
// other domain's root says nothing about this one, even though it is a perfectly valid credential.
func TestAttestationRejectsAnotherDomainsRoot(t *testing.T) {
	ourRoot, theirRoot, bridgeKP := mustKP(t), mustKP(t), mustKP(t)
	rec := signedClassification(t, bridgeKP, issueBridgeCred(t, theirRoot, bridgeKP.Ed25519Public))

	if v := bridge.VerifyClassificationAttestation(rec, ourRoot.Ed25519Public); v.Verified {
		t.Fatal("a credential signed by a different domain's root was accepted")
	}
}

// TestAttestationRequiresTheBridgeRole stops any credential the root ever signed — a routing
// credential, an address credential — from doubling as bridge authority.
func TestAttestationRequiresTheBridgeRole(t *testing.T) {
	root, bridgeKP := mustKP(t), mustKP(t)
	rec := signedClassification(t, bridgeKP, issueBridgeCred(t, root, bridgeKP.Ed25519Public, identity.RoleRouting))

	v := bridge.VerifyClassificationAttestation(rec, root.Ed25519Public)
	if v.Verified {
		t.Fatal("a routing credential was accepted as bridge authority")
	}
	if !strings.Contains(v.Reason, "bridge role") {
		t.Errorf("unhelpful reason: %s", v.Reason)
	}
}

// TestAttestationRejectsATamperedVerdict is the point of signing the record at all: the verdict
// must not be editable in flight by whoever is carrying it.
func TestAttestationRejectsATamperedVerdict(t *testing.T) {
	root, bridgeKP := mustKP(t), mustKP(t)
	rec := signedClassification(t, bridgeKP, issueBridgeCred(t, root, bridgeKP.Ed25519Public))

	rec.TrustTier = bridge.TrustTierSuspicious // change the claim without re-signing
	if v := bridge.VerifyClassificationAttestation(rec, root.Ed25519Public); v.Verified {
		t.Fatal("an edited trust tier survived verification")
	}
}

// TestAttestationSurvivesTheWire covers the credential actually round-tripping through protobuf —
// it rides in a field the bridge signature deliberately does not cover, so a marshalling bug here
// would silently strip it and turn every bridged message untrusted.
func TestAttestationSurvivesTheWire(t *testing.T) {
	root, bridgeKP := mustKP(t), mustKP(t)
	rec := signedClassification(t, bridgeKP, issueBridgeCred(t, root, bridgeKP.Ed25519Public))

	raw, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := bridge.UnmarshalClassificationRecord(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.BridgeCredential == nil {
		t.Fatal("the credential did not survive the round trip")
	}
	if v := bridge.VerifyClassificationAttestation(got, root.Ed25519Public); !v.Verified {
		t.Fatalf("a round-tripped record no longer verifies: %s", v.Reason)
	}
}

// TestDeliveryReceiptVerification covers the outbound direction. Without it a receipt is an
// unauthenticated claim that mail was delivered, which is worth nothing to the sender relying on
// it — and worse than nothing if it falsely claims success.
func TestDeliveryReceiptVerification(t *testing.T) {
	root, bridgeKP, attacker := mustKP(t), mustKP(t), mustKP(t)
	cred := issueBridgeCred(t, root, bridgeKP.Ed25519Public)

	mk := func(signer *identity.IdentityKeyPair, c *identity.Credential) *bridge.BridgeDeliveryReceipt {
		r := &bridge.BridgeDeliveryReceipt{
			RecipientEmail:   "someone@legacy.example",
			BridgeAddress:    "12D3KooWFakePeerID",
			DeliveredAt:      time.Now().UTC().Truncate(time.Second),
			Success:          true,
			BridgeCredential: c,
		}
		if err := r.Sign(signer.Ed25519Private); err != nil {
			t.Fatalf("sign receipt: %v", err)
		}
		return r
	}

	if v := bridge.VerifyDeliveryReceipt(mk(bridgeKP, cred), root.Ed25519Public); !v.Verified {
		t.Fatalf("a genuine receipt was rejected: %s", v.Reason)
	} else if !v.Success {
		t.Error("verdict lost the success flag")
	}
	if v := bridge.VerifyDeliveryReceipt(mk(bridgeKP, nil), root.Ed25519Public); v.Verified {
		t.Error("a receipt with no credential was trusted")
	}
	// An attacker's receipt carrying the real bridge's credential: the signature will not match
	// the credential's subject.
	if v := bridge.VerifyDeliveryReceipt(mk(attacker, cred), root.Ed25519Public); v.Verified {
		t.Error("a receipt signed by a key other than the credential's subject was trusted")
	}
	if v := bridge.VerifyDeliveryReceipt(nil, root.Ed25519Public); v.Verified {
		t.Error("a nil receipt verified")
	}
}

// TestNoBridgeMailboxAnywhere is the regression guard for what this change removed. A bridge used
// to hold `bridge@<domain>` and be looked up in the directory like a correspondent, which is what
// made attestation verification depend on a live registry and forced infrastructure to be
// provisioned like a person. If an address creeps back into these records, this fails.
func TestNoBridgeMailboxAnywhere(t *testing.T) {
	root, bridgeKP := mustKP(t), mustKP(t)
	rec := signedClassification(t, bridgeKP, issueBridgeCred(t, root, bridgeKP.Ed25519Public))

	if strings.Contains(rec.BridgeAddress, "@") {
		t.Errorf("BridgeAddress %q looks like an email address; it must be a libp2p peer ID", rec.BridgeAddress)
	}
	// And verification must not consult anything but the record and the domain root — proven by
	// the fact that every test here passes one keypair and no registry at all.
	if v := bridge.VerifyClassificationAttestation(rec, root.Ed25519Public); !v.Verified {
		t.Fatalf("verification needed something beyond the record and the root: %s", v.Reason)
	}
}
