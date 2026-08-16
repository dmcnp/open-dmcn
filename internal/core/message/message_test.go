package message

import (
	"bytes"
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/dmcnpb"
	"google.golang.org/protobuf/proto"
)

// helper to create a signed message for testing
func createTestSignedMessage(t *testing.T, kp *identity.IdentityKeyPair) *SignedMessage {
	t.Helper()

	msg, err := NewPlaintextMessage(
		"alice@example.com",
		"bob@example.com",
		"Hello Bob",
		"This is a test message from Alice to Bob.",
		kp.Ed25519Public,
	)
	if err != nil {
		t.Fatalf("NewPlaintextMessage: %v", err)
	}

	sm := &SignedMessage{Plaintext: *msg}
	if err := sm.Sign(kp.Ed25519Private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sm
}

func TestNewPlaintextMessage(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	msg, err := NewPlaintextMessage(
		"alice@example.com",
		"bob@example.com",
		"Test Subject",
		"Test body",
		kp.Ed25519Public,
	)
	if err != nil {
		t.Fatalf("NewPlaintextMessage: %v", err)
	}

	if msg.Version != 1 {
		t.Errorf("Version = %d, want 1", msg.Version)
	}
	if msg.MessageID == [16]byte{} {
		t.Error("MessageID is zero")
	}
	if msg.ThreadID == [16]byte{} {
		t.Error("ThreadID is zero")
	}
	if msg.SenderAddress != "alice@example.com" {
		t.Errorf("SenderAddress = %q", msg.SenderAddress)
	}
	if msg.RecipientAddress != "bob@example.com" {
		t.Errorf("RecipientAddress = %q", msg.RecipientAddress)
	}
	if msg.Subject != "Test Subject" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	if string(msg.Body.Content) != "Test body" {
		t.Errorf("Body.Content = %q", msg.Body.Content)
	}
	if msg.Body.ContentType != "text/plain" {
		t.Errorf("Body.ContentType = %q", msg.Body.ContentType)
	}
}

func TestSignedMessageSignAndVerify(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	sm := createTestSignedMessage(t, kp)

	if err := sm.Verify(); err != nil {
		t.Errorf("Verify() on freshly signed message: %v", err)
	}
}

func TestSignedMessageTamperDetection(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	sm := createTestSignedMessage(t, kp)

	// Tamper with the subject
	sm.Plaintext.Subject = "Tampered Subject"
	if err := sm.Verify(); err == nil {
		t.Error("Verify() should fail after tampering subject")
	}
}

func TestSignedMessageWrongKey(t *testing.T) {
	kp1, _ := identity.GenerateIdentityKeyPair()
	kp2, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, kp1)

	// Replace sender public key with a different one
	sm.Plaintext.SenderPublicKey = kp2.Ed25519Public
	if err := sm.Verify(); err == nil {
		t.Error("Verify() should fail with wrong public key")
	}
}

// PRD Test 3: Round-trip — compose PlaintextMessage → Sign → Encrypt to one
// recipient → Decrypt → Verify signature succeeds, plaintext matches.
func TestMessageRoundTrip(t *testing.T) {
	// Generate sender and recipient identities
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	// Compose and sign
	sm := createTestSignedMessage(t, senderKP)
	originalSubject := sm.Plaintext.Subject
	originalBody := string(sm.Plaintext.Body.Content)

	// Encrypt to one recipient
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, err := Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := Decrypt(env, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// Verify signature
	if err := decrypted.Verify(); err != nil {
		t.Errorf("Verify() after decrypt: %v", err)
	}

	// Plaintext matches
	if decrypted.Plaintext.Subject != originalSubject {
		t.Errorf("Subject = %q, want %q", decrypted.Plaintext.Subject, originalSubject)
	}
	if string(decrypted.Plaintext.Body.Content) != originalBody {
		t.Errorf("Body = %q, want %q", string(decrypted.Plaintext.Body.Content), originalBody)
	}
	if decrypted.Plaintext.SenderAddress != "alice@example.com" {
		t.Errorf("SenderAddress = %q", decrypted.Plaintext.SenderAddress)
	}
	if decrypted.Plaintext.RecipientAddress != "bob@example.com" {
		t.Errorf("RecipientAddress = %q", decrypted.Plaintext.RecipientAddress)
	}
}

// PRD Test 4: Multi-device — Encrypt to three recipients → each can
// independently Decrypt and verify.
func TestMultiDevice(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()

	// Create three recipient devices
	type device struct {
		kp *identity.IdentityKeyPair
	}
	devices := make([]device, 3)
	recipients := make([]RecipientInfo, 3)
	for i := range devices {
		kp, _ := identity.GenerateIdentityKeyPair()
		devices[i] = device{kp: kp}
		recipients[i] = RecipientInfo{
			DeviceID:  kp.DeviceID,
			X25519Pub: kp.X25519Public,
		}
	}

	sm := createTestSignedMessage(t, senderKP)
	originalBody := string(sm.Plaintext.Body.Content)

	env, err := Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if len(env.Recipients) != 3 {
		t.Fatalf("Recipients count = %d, want 3", len(env.Recipients))
	}

	// Each device should be able to decrypt independently
	for i, d := range devices {
		decrypted, err := Decrypt(env, d.kp.X25519Private, d.kp.X25519Public)
		if err != nil {
			t.Fatalf("device %d Decrypt: %v", i, err)
		}

		if err := decrypted.Verify(); err != nil {
			t.Errorf("device %d Verify: %v", i, err)
		}

		if string(decrypted.Plaintext.Body.Content) != originalBody {
			t.Errorf("device %d body mismatch", i)
		}
	}
}

// PRD Test 5: Wrong key — Decrypt with a key not in Recipients returns
// a typed error, not a panic.
func TestWrongKey(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	wrongKP, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, senderKP)
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, err := Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Try to decrypt with a key not in the recipients
	_, err = Decrypt(env, wrongKP.X25519Private, wrongKP.X25519Public)
	if err == nil {
		t.Fatal("Decrypt() with wrong key should fail")
	}

	if !errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("error = %v, want ErrRecipientNotFound", err)
	}
}

// PRD Test 6: Tamper — mutating EncryptedPayload causes Decrypt to
// return an authentication error.
func TestPayloadTamper(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, senderKP)
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, err := Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with the encrypted payload
	if len(env.EncryptedPayload) > 0 {
		env.EncryptedPayload[0] ^= 0xff
	}

	_, err = Decrypt(env, recipientKP.X25519Private, recipientKP.X25519Public)
	if err == nil {
		t.Fatal("Decrypt() with tampered payload should fail")
	}

	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("error = %v, want ErrDecryptionFailed", err)
	}
}

// PRD Test 7: RatchetPubKey — serialise and deserialise an EncryptedEnvelope
// and confirm RatchetPubKey is present as 32 zero bytes.
func TestRatchetPubKey(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, senderKP)
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, err := Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Verify RatchetPubKey is zero
	if !env.EnvelopeRatchetPubKeyIsZero() {
		t.Error("RatchetPubKey should be all zeros in v1")
	}

	// Serialize to protobuf
	pb := env.ToProto()
	data, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	// Deserialize
	pb2 := &dmcnpb.EncryptedEnvelope{}
	if err := proto.Unmarshal(data, pb2); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	// Convert back
	env2, err := EncryptedEnvelopeFromProto(pb2)
	if err != nil {
		t.Fatalf("EncryptedEnvelopeFromProto: %v", err)
	}

	// RatchetPubKey should still be 32 zero bytes
	if !env2.EnvelopeRatchetPubKeyIsZero() {
		t.Error("RatchetPubKey should be all zeros after round-trip")
	}

	// Verify it's exactly 32 bytes of zeros
	expectedZero := [32]byte{}
	if env2.RatchetPubKey != expectedZero {
		t.Errorf("RatchetPubKey = %x, want 32 zero bytes", env2.RatchetPubKey)
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	sm := createTestSignedMessage(t, senderKP)

	_, err := Encrypt(sm, nil)
	if err == nil {
		t.Error("Encrypt() with no recipients should fail")
	}
}

func TestSelectSizeClass(t *testing.T) {
	// Boundaries account for padPayload's 4-byte length prefix: a payload of
	// exactly a class size needs the next class up so its tail is not truncated.
	tests := []struct {
		size uint32
		want uint32
	}{
		{0, 1024},
		{100, 1024},
		{1020, 1024},
		{1021, 4096}, // 1021+4 > 1024
		{1024, 4096},
		{4092, 4096},
		{4093, 16384},
		{16380, 16384},
		{65532, 65536},
		{262140, 262144},
		{1048572, 1048576},
		{1048573, 2 * 1048576}, // 1048573+4 > 1 MB → rounds up to nearest MB
	}

	for _, tt := range tests {
		got := selectSizeClass(tt.size)
		if got != tt.want {
			t.Errorf("selectSizeClass(%d) = %d, want %d", tt.size, got, tt.want)
		}
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	payload := []byte("hello world")
	padded := padPayload(payload, 1024)

	if len(padded) != 1024 {
		t.Errorf("padded length = %d, want 1024", len(padded))
	}

	unpadded := unpadPayload(padded)
	if !bytes.Equal(unpadded, payload) {
		t.Errorf("unpadded = %q, want %q", unpadded, payload)
	}
}

func TestEncryptedEnvelopeProtoRoundTrip(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, senderKP)
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, _ := Encrypt(sm, recipients)

	// Proto round-trip
	pb := env.ToProto()
	data, _ := proto.Marshal(pb)
	pb2 := &dmcnpb.EncryptedEnvelope{}
	proto.Unmarshal(data, pb2)
	env2, _ := EncryptedEnvelopeFromProto(pb2)

	// Should still be decryptable
	decrypted, err := Decrypt(env2, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("Decrypt after proto round-trip: %v", err)
	}

	if err := decrypted.Verify(); err != nil {
		t.Errorf("Verify after proto round-trip: %v", err)
	}
}

func TestEncryptedEnvelopeFromProtoNil(t *testing.T) {
	_, err := EncryptedEnvelopeFromProto(nil)
	if err == nil {
		t.Error("EncryptedEnvelopeFromProto(nil) should fail")
	}
}

func TestEnvelopeVersion(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, senderKP)
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, _ := Encrypt(sm, recipients)
	if env.Version != 1 {
		t.Errorf("Version = %d, want 1", env.Version)
	}
}

func TestEnvelopePayloadSizeClass(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, senderKP)
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, _ := Encrypt(sm, recipients)

	// Size class should be one of the defined buckets
	validClasses := map[uint32]bool{1024: true, 4096: true, 16384: true, 65536: true, 262144: true, 1048576: true}
	if !validClasses[env.PayloadSizeClass] {
		t.Errorf("PayloadSizeClass = %d, not a valid size class", env.PayloadSizeClass)
	}
}

func TestMessageWithAttachments(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	msg, _ := NewPlaintextMessage(
		"alice@example.com",
		"bob@example.com",
		"With Attachment",
		"See attached.",
		kp.Ed25519Public,
	)

	// Add attachment
	msg.Attachments = []AttachmentRecord{
		{
			AttachmentID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Filename:     "test.txt",
			ContentType:  "text/plain",
			SizeBytes:    11,
			ContentHash:  [32]byte{0xaa, 0xbb},
			Content:      []byte("hello world"),
		},
	}

	sm := &SignedMessage{Plaintext: *msg}
	sm.Sign(kp.Ed25519Private)

	// Encrypt and decrypt
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}
	env, err := Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := Decrypt(env, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if err := decrypted.Verify(); err != nil {
		t.Errorf("Verify: %v", err)
	}

	if len(decrypted.Plaintext.Attachments) != 1 {
		t.Fatalf("Attachments count = %d, want 1", len(decrypted.Plaintext.Attachments))
	}

	att := decrypted.Plaintext.Attachments[0]
	if att.Filename != "test.txt" {
		t.Errorf("Filename = %q", att.Filename)
	}
	if string(att.Content) != "hello world" {
		t.Errorf("Content = %q", string(att.Content))
	}
}

func TestUnpadPayloadEdgeCases(t *testing.T) {
	// Too short
	short := []byte{0, 0}
	if result := unpadPayload(short); !bytes.Equal(result, short) {
		t.Error("unpadPayload should return input when too short")
	}

	// Length exceeds buffer
	bad := []byte{0, 0, 0, 255, 0} // claims 255 bytes but buffer has 1
	if result := unpadPayload(bad); !bytes.Equal(result, bad) {
		t.Error("unpadPayload should return input when length exceeds buffer")
	}
}

func TestMessageProtoConversions(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	msg, _ := NewPlaintextMessage(
		"alice@example.com",
		"bob@example.com",
		"Test",
		"Body text",
		kp.Ed25519Public,
	)
	msg.ReplyToID = [16]byte{1, 2, 3}

	sm := &SignedMessage{Plaintext: *msg}
	sm.Sign(kp.Ed25519Private)

	// Test toProto and back
	pb := sm.toProto()
	sm2 := signedMessageFromProto(pb)

	if sm2.Plaintext.SenderAddress != msg.SenderAddress {
		t.Errorf("SenderAddress = %q", sm2.Plaintext.SenderAddress)
	}
	if sm2.Plaintext.ReplyToID != msg.ReplyToID {
		t.Errorf("ReplyToID mismatch")
	}
	if sm2.Plaintext.Body.ContentType != "text/plain" {
		t.Errorf("ContentType = %q", sm2.Plaintext.Body.ContentType)
	}

	// Verify signature survives conversion
	if err := sm2.Verify(); err != nil {
		t.Errorf("Verify after proto conversion: %v", err)
	}
}

func TestCEKTamper(t *testing.T) {
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()

	sm := createTestSignedMessage(t, senderKP)
	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	env, _ := Encrypt(sm, recipients)

	// Tamper with wrapped CEK
	if len(env.Recipients[0].WrappedCEK) > 0 {
		env.Recipients[0].WrappedCEK[0] ^= 0xff
	}

	_, err := Decrypt(env, recipientKP.X25519Private, recipientKP.X25519Public)
	if err == nil {
		t.Fatal("Decrypt with tampered CEK should fail")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("error = %v, want ErrDecryptionFailed", err)
	}
}

func TestSignMarshalFailure(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	sm := createTestSignedMessage(t, kp)

	old := protoMarshal
	protoMarshal = func(m proto.Message) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	defer func() { protoMarshal = old }()

	newSm := &SignedMessage{Plaintext: sm.Plaintext}
	if err := newSm.Sign(kp.Ed25519Private); err == nil {
		t.Error("Sign() should fail when marshal fails")
	}
}

func TestVerifyMarshalFailure(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	sm := createTestSignedMessage(t, kp)

	old := protoMarshal
	protoMarshal = func(m proto.Message) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	defer func() { protoMarshal = old }()

	if err := sm.Verify(); err == nil {
		t.Error("Verify() should fail when marshal fails")
	}
}

func TestEncryptMarshalFailure(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	sm := createTestSignedMessage(t, kp)

	old := protoMarshal
	protoMarshal = func(m proto.Message) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	defer func() { protoMarshal = old }()

	recipients := []RecipientInfo{{
		DeviceID:  recipientKP.DeviceID,
		X25519Pub: recipientKP.X25519Public,
	}}

	_, err := Encrypt(sm, recipients)
	if err == nil {
		t.Error("Encrypt() should fail when marshal fails")
	}
}

func TestSignWithInvalidKey(t *testing.T) {
	kp, _ := identity.GenerateIdentityKeyPair()
	msg, _ := NewPlaintextMessage(
		"alice@example.com",
		"bob@example.com",
		"Test",
		"Body",
		kp.Ed25519Public,
	)

	sm := &SignedMessage{Plaintext: *msg}
	err := sm.Sign([]byte("short")) // invalid key size
	if err == nil {
		t.Error("Sign() with invalid key should fail")
	}
}
