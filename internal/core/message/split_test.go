package message

import (
	"bytes"
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

func TestPayloadPaddingRoundTripAtBoundaries(t *testing.T) {
	// Sizes at and just below size-class boundaries are where the 4-byte length
	// prefix used to truncate the tail.
	for _, n := range []int{0, 1, 1020, 1021, 1024, 4096, 16384, 1 << 20} {
		payload := bytes.Repeat([]byte{0xab}, n)
		sc := selectSizeClass(uint32(n))
		if sc < uint32(n)+4 {
			t.Fatalf("size %d: class %d does not leave room for the length prefix", n, sc)
		}
		got := unpadPayload(padPayload(payload, sc))
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d (class %d): round-trip mismatch, got %d bytes", n, sc, len(got))
		}
	}
}

func TestSplitLargeBodyRoundTrip(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)
	big, err := crypto.RandomBytes(5 << 20) // 5 MB: past the 1 MB top size class and the 4 MB wire cap
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := NewPlaintextMessage("a@x", "b@x", "big", "", senderPub)
	msg.Body = MessageBody{ContentType: "application/octet-stream", Content: big}

	sh, content, err := Split(msg, senderPriv)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatalf("EncryptSplit: %v", err)
	}
	gotH, err := DecryptHeader(env, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("DecryptHeader: %v", err)
	}
	gotC, err := DecryptBody(env, &gotH.Header, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
	if !bytes.Equal(gotC.Body.Content, big) {
		t.Fatal("5 MB body did not round-trip byte-identical")
	}
}

func splitTestKeys(t *testing.T) (senderPub, senderPriv []byte, rxPub, rxPriv [32]byte) {
	t.Helper()
	ePub, ePriv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	xPub, xPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return ePub, ePriv, xPub, xPriv
}

func TestSplitRoundTrip(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)

	msg, err := NewPlaintextMessage("alice@dmcn.me", "bob@dmcn.me", "Hello", "this is the body content for the preview and beyond", senderPub)
	if err != nil {
		t.Fatal(err)
	}
	msg.Attachments = append(msg.Attachments, AttachmentRecord{Filename: "a.txt", ContentType: "text/plain", SizeBytes: 3, Content: []byte("abc")})

	sh, content, err := Split(msg, senderPriv)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if sh.Header.Subject != "Hello" || sh.Header.AttachmentCount != 1 {
		t.Fatalf("header preview fields wrong: %+v", sh.Header)
	}
	if sh.Header.Snippet == "" {
		t.Fatal("expected a non-empty snippet for a text body")
	}
	if err := sh.Verify(); err != nil {
		t.Fatalf("header should verify: %v", err)
	}

	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatalf("EncryptSplit: %v", err)
	}
	if !env.IsSplit() {
		t.Fatal("envelope should report IsSplit")
	}

	// Preview: decrypt + verify the header WITHOUT the body.
	gotH, err := DecryptHeader(env, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("DecryptHeader: %v", err)
	}
	if gotH.Header.Subject != "Hello" || gotH.Header.SenderAddress != "alice@dmcn.me" || gotH.Header.Snippet != sh.Header.Snippet {
		t.Fatalf("decrypted header mismatch: %+v", gotH.Header)
	}

	// Body, verified against the header's commitment.
	gotC, err := DecryptBody(env, &gotH.Header, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
	if string(gotC.Body.Content) != string(msg.Body.Content) {
		t.Fatal("body content mismatch")
	}
	if len(gotC.Attachments) != 1 || gotC.Attachments[0].Filename != "a.txt" {
		t.Fatal("attachment mismatch")
	}
}

func TestRecipientListsRoundTripAndTamper(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)
	msg, err := NewPlaintextMessage("alice@dmcn.me", "bob@dmcn.me", "Hi all", "body", senderPub)
	if err != nil {
		t.Fatal(err)
	}
	sh, content, err := Split(msg, senderPriv)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	// The recipient lists are set on the header after Split (PlaintextMessage has no
	// list fields); EncryptSplit re-signs, so they become signature-protected.
	sh.Header.To = []string{"bob@dmcn.me", "carol@dmcn.me"}
	sh.Header.Cc = []string{"dave@dmcn.me"}
	sh.Header.Bcc = []string{"eve@dmcn.me"} // e.g. a Sent self-copy

	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatalf("EncryptSplit: %v", err)
	}
	gotH, err := DecryptHeader(env, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("DecryptHeader: %v", err)
	}
	if len(gotH.Header.To) != 2 || gotH.Header.To[0] != "bob@dmcn.me" || gotH.Header.To[1] != "carol@dmcn.me" {
		t.Fatalf("To did not round-trip: %v", gotH.Header.To)
	}
	if len(gotH.Header.Cc) != 1 || gotH.Header.Cc[0] != "dave@dmcn.me" {
		t.Fatalf("Cc did not round-trip: %v", gotH.Header.Cc)
	}
	if len(gotH.Header.Bcc) != 1 || gotH.Header.Bcc[0] != "eve@dmcn.me" {
		t.Fatalf("Bcc did not round-trip: %v", gotH.Header.Bcc)
	}

	// Tampering with the recipient list must break verification (the lists are
	// covered by the header signature).
	tampered := *gotH
	tampered.Header.To = append([]string{"mallory@evil.example"}, tampered.Header.To...)
	if err := tampered.Verify(); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered To list should fail verification, got %v", err)
	}
}

func TestSignedHeaderTamperEvident(t *testing.T) {
	senderPub, senderPriv, _, _ := splitTestKeys(t)
	sh := &SignedHeader{Header: MessageHeader{Version: 1, SenderAddress: "alice@dmcn.me", SenderPublicKey: senderPub, Subject: "real"}}
	if err := sh.Sign(senderPriv); err != nil {
		t.Fatal(err)
	}
	if err := sh.Verify(); err != nil {
		t.Fatalf("valid header should verify: %v", err)
	}
	sh.Header.Subject = "tampered"
	if err := sh.Verify(); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered header should fail verification, got %v", err)
	}
}

func TestSplitCiphertextTamperFails(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)
	msg, _ := NewPlaintextMessage("a@x", "b@x", "s", "body", senderPub)
	sh, content, _ := Split(msg, senderPriv)
	env, _ := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)

	bad := *env
	bad.EncryptedHeader = append([]byte(nil), env.EncryptedHeader...)
	bad.EncryptedHeader[0] ^= 0xff
	if _, err := DecryptHeader(&bad, rxPriv, rxPub); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered header ciphertext should fail AEAD, got %v", err)
	}

	bad2 := *env
	bad2.EncryptedBody = append([]byte(nil), env.EncryptedBody...)
	bad2.EncryptedBody[0] ^= 0xff
	if _, err := DecryptBody(&bad2, &sh.Header, rxPriv, rxPub); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("tampered body ciphertext should fail AEAD, got %v", err)
	}
}

func TestSplitBodyHashMismatch(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)
	msg, _ := NewPlaintextMessage("a@x", "b@x", "s", "body", senderPub)
	sh, content, _ := Split(msg, senderPriv)
	env, _ := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)

	bad := sh.Header
	bad.BodyHash[0] ^= 0xff
	if _, err := DecryptBody(env, &bad, rxPriv, rxPub); !errors.Is(err, ErrBodyHashMismatch) {
		t.Fatalf("body must be rejected when it does not match the header hash, got %v", err)
	}
}

func TestSplitWrongRecipient(t *testing.T) {
	senderPub, senderPriv, rxPub, _ := splitTestKeys(t)
	_, otherPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := NewPlaintextMessage("a@x", "b@x", "s", "body", senderPub)
	sh, content, _ := Split(msg, senderPriv)
	env, _ := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)

	var otherPub [32]byte // not in the recipient list
	if _, err := DecryptHeader(env, otherPriv, otherPub); !errors.Is(err, ErrRecipientNotFound) {
		t.Fatalf("non-recipient should get ErrRecipientNotFound, got %v", err)
	}
}
