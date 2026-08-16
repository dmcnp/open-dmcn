package message

import (
	"bytes"
	"encoding/json"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// TestSealedBlobDualRecipient proves the recipient-filter custody model: a blob
// sealed to BOTH an owner key and a mailbox key opens with EITHER private key, a
// non-recipient key cannot open it, and the blob survives a JSON round-trip (as it
// must, being stored server-side and returned to the browser as ciphertext).
func TestSealedBlobDualRecipient(t *testing.T) {
	ownerPub, ownerPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mboxPub, mboxPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	strangerPub, strangerPriv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte(`{"mode":"deny","domains":["evil.com"]}`)
	blob, err := SealToRecipients(plaintext, [][32]byte{ownerPub, mboxPub})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// JSON round-trip (server stores + returns ciphertext).
	raw, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	var rt SealedBlob
	if err := json.Unmarshal(raw, &rt); err != nil {
		t.Fatal(err)
	}

	// Owner opens it (any device with the identity key).
	if got, err := OpenSealed(&rt, ownerPriv, ownerPub); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("owner open = (%q, %v), want plaintext", got, err)
	}
	// Mailbox opens it (to enforce the filter at STORE).
	if got, err := OpenSealed(&rt, mboxPriv, mboxPub); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("mailbox open = (%q, %v), want plaintext", got, err)
	}
	// A stranger cannot.
	if _, err := OpenSealed(&rt, strangerPriv, strangerPub); err == nil {
		t.Fatal("a non-recipient key must not open the sealed blob")
	}
}
