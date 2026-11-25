package pairing

import (
	"bytes"
	"regexp"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// fixed test vectors — asserted byte-identically by the browser mirror in
// cmd/dmcnd/web/src/lib/crypto/pairing.test.ts.
var (
	goldenAccount = "vector@parity.example"
	goldenEphEd   = bytes.Repeat([]byte{0x01}, 32)
	goldenEphX    = bytes.Repeat([]byte{0x02}, 32)
	// goldenSAS is locked so the web mirror (confirmationCode in pairing.ts) can
	// assert byte-identical output for the same inputs.
	goldenSAS = "2309-4949-8238"
)

func TestConfirmationCodeGolden(t *testing.T) {
	got := ConfirmationCode(goldenAccount, goldenEphEd, goldenEphX)
	if got != goldenSAS {
		t.Fatalf("SAS golden mismatch: got %q want %q (update goldenSAS AND the TS mirror together)", got, goldenSAS)
	}
}

func TestConfirmationCodeFormatAndDeterminism(t *testing.T) {
	re := regexp.MustCompile(`^\d{4}-\d{4}-\d{4}$`)
	a := ConfirmationCode("alice@dmcn.me", goldenEphX, goldenEphEd)
	b := ConfirmationCode("alice@dmcn.me", goldenEphX, goldenEphEd)
	if a != b {
		t.Fatalf("not deterministic: %q != %q", a, b)
	}
	if !re.MatchString(a) {
		t.Fatalf("bad format: %q", a)
	}
}

func TestConfirmationCodeBindsInputs(t *testing.T) {
	base := ConfirmationCode(goldenAccount, goldenEphEd, goldenEphX)
	if ConfirmationCode("other@dmcn.me", goldenEphEd, goldenEphX) == base {
		t.Fatal("code did not change with account address")
	}
	if ConfirmationCode(goldenAccount, goldenEphX, goldenEphX) == base {
		t.Fatal("code did not change with ephemeral ed key")
	}
	if ConfirmationCode(goldenAccount, goldenEphEd, goldenEphEd) == base {
		t.Fatal("code did not change with ephemeral x key")
	}
}

func TestEphemeralAddress(t *testing.T) {
	a, err := EphemeralAddress()
	if err != nil {
		t.Fatal(err)
	}
	b, err := EphemeralAddress()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("ephemeral addresses must be unique")
	}
	// must be a valid address that NewIdentityRecord accepts
	kp, _ := identity.GenerateIdentityKeyPair()
	if _, err := identity.NewIdentityRecord(a, kp); err != nil {
		t.Fatalf("ephemeral address rejected by NewIdentityRecord: %v", err)
	}
}

func TestNewEphemeralRecordSelfSigns(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	addr, _ := EphemeralAddress()
	now := time.Now()
	rec, err := NewEphemeralRecord(addr, kp, "/ip4/127.0.0.1/tcp/7400/p2p/xyz", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("ephemeral record self-signature invalid: %v", err)
	}
	if rec.VerificationTier != identity.TierUnverified {
		t.Fatalf("expected tier 0, got %v", rec.VerificationTier)
	}
	if len(rec.RelayHints) != 1 {
		t.Fatalf("expected 1 relay hint, got %d", len(rec.RelayHints))
	}
	if rec.ExpiresAt.Before(now) {
		t.Fatal("ephemeral record should expire in the future")
	}
}

func TestCloneRequestRoundTrip(t *testing.T) {
	eph, _ := identity.GenerateIdentityKeyPair()
	msg, err := BuildCloneRequestMessage(eph, "pair-x@pairing.local", goldenAccount, "Chrome on Mac")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != SubjectRequest {
		t.Fatalf("subject = %q", msg.Subject)
	}
	content := &message.MessageContent{Body: msg.Body, Attachments: msg.Attachments}
	d, ok := ExtractCloneRequest(content)
	if !ok {
		t.Fatal("failed to extract clone request")
	}
	if !bytes.Equal(d.EphemeralEd25519Pub, eph.Ed25519Public) {
		t.Fatal("ed25519 pub mismatch")
	}
	if d.EphemeralX25519Pub != eph.X25519Public {
		t.Fatal("x25519 pub mismatch")
	}
	if d.DeviceID != eph.DeviceID {
		t.Fatal("device id mismatch")
	}
	if d.Label != "Chrome on Mac" {
		t.Fatalf("label = %q", d.Label)
	}
	// SAS computed from the extracted request must match the new device's own.
	if ConfirmationCode(goldenAccount, d.EphemeralEd25519Pub, d.EphemeralX25519Pub[:]) !=
		ConfirmationCode(goldenAccount, eph.Ed25519Public, eph.X25519Public[:]) {
		t.Fatal("SAS mismatch between request and origin")
	}
}

func TestCloneResponseRoundTrip(t *testing.T) {
	account, _ := identity.GenerateIdentityKeyPair()
	msg, err := BuildCloneResponseMessage(account, goldenAccount, "pair-x@pairing.local")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != SubjectApproval {
		t.Fatalf("subject = %q", msg.Subject)
	}
	content := &message.MessageContent{Body: msg.Body, Attachments: msg.Attachments}
	d, ok := ExtractCloneResponse(content)
	if !ok {
		t.Fatal("failed to extract clone response")
	}
	kp := d.KeyPair()
	if !bytes.Equal(kp.Ed25519Private, account.Ed25519Private) {
		t.Fatal("ed25519 private mismatch")
	}
	if kp.X25519Private != account.X25519Private {
		t.Fatal("x25519 private mismatch")
	}
	if kp.X25519Public != account.X25519Public {
		t.Fatal("x25519 public mismatch")
	}
	if d.Address != goldenAccount {
		t.Fatalf("address = %q", d.Address)
	}
}

func TestExtractIgnoresOtherAttachments(t *testing.T) {
	content := &message.MessageContent{
		Body:        message.MessageBody{ContentType: "text/plain", Content: []byte("hi")},
		Attachments: []message.AttachmentRecord{{ContentType: "image/png", Content: []byte{1, 2, 3}}},
	}
	if _, ok := ExtractCloneRequest(content); ok {
		t.Fatal("should not extract from unrelated attachment")
	}
	if _, ok := ExtractCloneResponse(content); ok {
		t.Fatal("should not extract from unrelated attachment")
	}
}
