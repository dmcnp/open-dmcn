package bridge

import (
	"testing"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// tBridgePeerID stands in for the bridge's libp2p peer ID. A bridge has no email address, so
// this field is informational — a fixture using an email would model a shape the protocol no
// longer has.
const tBridgePeerID = "12D3KooWBridgeTestPeerIDFixture0000000000000000"

func TestClassificationRecordSignVerify(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rec := &BridgeClassificationRecord{
		BridgeAddress:   tBridgePeerID,
		BridgePublicKey: pub,
		SMTPFrom:        "sender@gmail.com",
		SMTPSenderIP:    "1.2.3.4",
		SPFResult:       SPFPass,
		DKIMResult:      DKIMPass,
		DMARCResult:     DMARCPass,
		ReputationScore: 50,
		TrustTier:       TrustTierVerifiedLegacy,
	}

	if err := rec.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := rec.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestClassificationRecordTamper(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rec := &BridgeClassificationRecord{
		BridgeAddress:   tBridgePeerID,
		BridgePublicKey: pub,
		SMTPFrom:        "sender@gmail.com",
		TrustTier:       TrustTierVerifiedLegacy,
	}

	if err := rec.Sign(priv); err != nil {
		t.Fatal(err)
	}

	rec.TrustTier = TrustTierSuspicious
	if err := rec.Verify(); err == nil {
		t.Fatal("expected verify to fail after tampering")
	}
}

func TestClassificationRecordMarshalRoundTrip(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rec := &BridgeClassificationRecord{
		BridgeAddress:   tBridgePeerID,
		BridgePublicKey: pub,
		SMTPFrom:        "sender@gmail.com",
		SMTPSenderIP:    "10.0.0.1",
		SPFResult:       SPFSoftFail,
		DKIMResult:      DKIMNone,
		DMARCResult:     DMARCNone,
		TrustTier:       TrustTierUnverifiedLegacy,
	}
	if err := rec.Sign(priv); err != nil {
		t.Fatal(err)
	}

	data, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	rec2, err := UnmarshalClassificationRecord(data)
	if err != nil {
		t.Fatal(err)
	}

	if rec2.BridgeAddress != rec.BridgeAddress {
		t.Errorf("bridge address: got %q, want %q", rec2.BridgeAddress, rec.BridgeAddress)
	}
	if rec2.TrustTier != rec.TrustTier {
		t.Errorf("trust tier: got %d, want %d", rec2.TrustTier, rec.TrustTier)
	}
	if err := rec2.Verify(); err != nil {
		t.Fatalf("verify after roundtrip: %v", err)
	}
}

func TestDeliveryReceiptSignVerify(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rec := &BridgeDeliveryReceipt{
		OriginalMessageID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		RecipientEmail:    "bob@gmail.com",
		BridgeAddress:     "bridge@bridge.localhost",
		Success:           true,
	}

	if err := rec.Sign(priv); err != nil {
		t.Fatal(err)
	}

	if err := rec.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestDeliveryReceiptTamper(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rec := &BridgeDeliveryReceipt{
		RecipientEmail: "bob@gmail.com",
		BridgeAddress:  "bridge@bridge.localhost",
		Success:        true,
	}

	if err := rec.Sign(priv); err != nil {
		t.Fatal(err)
	}

	rec.Success = false
	if err := rec.Verify(pub); err == nil {
		t.Fatal("expected verify to fail after tampering")
	}
}

func TestDeliveryReceiptMarshalRoundTrip(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rec := &BridgeDeliveryReceipt{
		OriginalMessageID: [16]byte{1, 2, 3},
		RecipientEmail:    "bob@gmail.com",
		BridgeAddress:     "bridge@bridge.localhost",
		Success:           true,
	}
	if err := rec.Sign(priv); err != nil {
		t.Fatal(err)
	}

	data, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	rec2, err := UnmarshalDeliveryReceipt(data)
	if err != nil {
		t.Fatal(err)
	}

	if rec2.RecipientEmail != rec.RecipientEmail {
		t.Errorf("recipient: got %q, want %q", rec2.RecipientEmail, rec.RecipientEmail)
	}
	if rec2.Success != rec.Success {
		t.Errorf("success: got %v, want %v", rec2.Success, rec.Success)
	}
	if err := rec2.Verify(pub); err != nil {
		t.Fatalf("verify after roundtrip: %v", err)
	}
}
