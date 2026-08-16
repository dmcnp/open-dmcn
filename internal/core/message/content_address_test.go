package message

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// TestBodyContentAddressLayout pins the on-wire content address for a fixed blob:
// CIDv1(raw, sha2-256) = 0x01 0x55 0x12 0x20 || SHA-256(body_nonce||ct||tag). It
// cross-checks the go-cid/go-multihash output against an independently hand-built
// CID (stdlib sha256 + literal prefix) and asserts determinism. The logged golden
// hex is mirrored in the frontend parity test for Go↔TS interop.
func TestBodyContentAddressLayout(t *testing.T) {
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	ct := []byte("content-addressing precondition")
	tag := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}

	got, err := ComputeBodyContentAddress(nonce, ct, tag)
	if err != nil {
		t.Fatalf("ComputeBodyContentAddress: %v", err)
	}

	// Hand-built CIDv1/raw/sha2-256 — a different code path than go-cid/go-multihash.
	blob := append(append(append([]byte{}, nonce...), ct...), tag...)
	sum := sha256.Sum256(blob)
	want := append([]byte{0x01, 0x55, 0x12, 0x20}, sum[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("content address layout mismatch:\n got %x\nwant %x", got, want)
	}
	if len(got) != 36 {
		t.Fatalf("expected a 36-byte CIDv1, got %d", len(got))
	}

	// Determinism: identical bytes -> identical address, always.
	again, _ := ComputeBodyContentAddress(nonce, ct, tag)
	if !bytes.Equal(got, again) {
		t.Fatal("content address is not deterministic for identical input")
	}

	t.Logf("body content address golden = %s", hex.EncodeToString(got))
}

// TestEncryptSplitContentAddress covers the seal: the body is content-addressed,
// the address is carried in the clear, committed in the signed header, and the
// header signature covers it (snapshot binding). It also confirms the full
// decrypt path passes the new bind.
func TestEncryptSplitContentAddress(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)
	msg, _ := NewPlaintextMessage("a@x", "b@x", "subj", "hello body", senderPub)
	sh, content, err := Split(msg, senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Cleartext copy matches the recomputed body blob, and the keyless check passes.
	wantAddr, _ := ComputeBodyContentAddress(env.BodyNonce[:], env.EncryptedBody, env.BodyTag[:])
	if !bytes.Equal(env.BodyContentAddress, wantAddr) {
		t.Fatal("envelope cleartext content address does not match its body blob")
	}
	if err := env.VerifyBodyContentAddress(); err != nil {
		t.Fatalf("keyless verify of a freshly sealed envelope failed: %v", err)
	}

	// Signed copy matches and is decryptable.
	gotH, err := DecryptHeader(env, rxPriv, rxPub)
	if err != nil {
		t.Fatalf("DecryptHeader: %v", err)
	}
	if !bytes.Equal(gotH.Header.BodyContentAddress, wantAddr) {
		t.Fatal("signed header content address does not match the body blob")
	}

	// Snapshot binding: mutating the committed address invalidates the signature.
	tampered := *gotH
	tampered.Header.BodyContentAddress = append([]byte(nil), wantAddr...)
	tampered.Header.BodyContentAddress[5] ^= 0xff
	if err := tampered.Verify(); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("header signature must cover body_content_address; got %v", err)
	}

	if _, err := DecryptBody(env, &gotH.Header, rxPriv, rxPub); err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
}

// TestEncryptSplitOneAddressManyRecipients is the dedup precondition (value form):
// one send produces one body blob and one address, and every recipient reads the
// same blob via that address. (The physical "one stored copy" is the deferred
// storage optimization, not asserted here.)
func TestEncryptSplitOneAddressManyRecipients(t *testing.T) {
	senderPub, senderPriv, rx1Pub, rx1Priv := splitTestKeys(t)
	rx2Pub, rx2Priv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	const body = "one body, two readers"
	msg, _ := NewPlaintextMessage("a@x", "b@x", "s", body, senderPub)
	sh, content, err := Split(msg, senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rx1Pub}, {X25519Pub: rx2Pub}}, senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	addr := append([]byte(nil), env.BodyContentAddress...)
	if len(addr) != 36 {
		t.Fatalf("expected a 36-byte content address, got %d", len(addr))
	}

	for _, r := range []struct {
		name      string
		priv, pub [32]byte
	}{{"rx1", rx1Priv, rx1Pub}, {"rx2", rx2Priv, rx2Pub}} {
		h, err := DecryptHeader(env, r.priv, r.pub)
		if err != nil {
			t.Fatalf("%s DecryptHeader: %v", r.name, err)
		}
		if !bytes.Equal(h.Header.BodyContentAddress, addr) {
			t.Fatalf("%s: each recipient must see the same signed content address", r.name)
		}
		c, err := DecryptBody(env, &h.Header, r.priv, r.pub)
		if err != nil {
			t.Fatalf("%s DecryptBody: %v", r.name, err)
		}
		if string(c.Body.Content) != body {
			t.Fatalf("%s: body mismatch", r.name)
		}
	}
}

// TestVerifyBodyContentAddressKeylessTamper: flipping a body byte changes the
// recomputed address but not the stored cleartext one, so a relay rejects it
// WITHOUT the CEK.
func TestVerifyBodyContentAddressKeylessTamper(t *testing.T) {
	senderPub, senderPriv, rxPub, _ := splitTestKeys(t)
	msg, _ := NewPlaintextMessage("a@x", "b@x", "s", "tamper me", senderPub)
	sh, content, _ := Split(msg, senderPriv)
	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.VerifyBodyContentAddress(); err != nil {
		t.Fatalf("clean envelope failed keyless verify: %v", err)
	}
	env.EncryptedBody[0] ^= 0xff
	if err := env.VerifyBodyContentAddress(); !errors.Is(err, ErrBodyAddressMismatch) {
		t.Fatalf("expected ErrBodyAddressMismatch after body tamper, got %v", err)
	}
}

// TestDecryptBodyAddressMismatch: DecryptBody rejects a body whose address does
// not match the (signed) header even when body_hash matches — the content address
// is an independent commitment.
func TestDecryptBodyAddressMismatch(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)
	msg, _ := NewPlaintextMessage("a@x", "b@x", "s", "legit body", senderPub)
	sh, content, _ := Split(msg, senderPriv)
	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	h, err := DecryptHeader(env, rxPriv, rxPub)
	if err != nil {
		t.Fatal(err)
	}
	// Header copy with a wrong address but a correct body_hash: the body decrypts
	// and matches body_hash, so only the address check can reject it.
	bad := h.Header
	bad.BodyContentAddress = append([]byte(nil), h.Header.BodyContentAddress...)
	bad.BodyContentAddress[7] ^= 0xff
	if _, err := DecryptBody(env, &bad, rxPriv, rxPub); !errors.Is(err, ErrBodyAddressMismatch) {
		t.Fatalf("expected ErrBodyAddressMismatch, got %v", err)
	}
}

// TestContentAddressFailOpen: pre-feature (empty/unknown address) and non-split
// envelopes pass the keyless check and skip the recipient address bind, so old
// senders keep working.
func TestContentAddressFailOpen(t *testing.T) {
	senderPub, senderPriv, rxPub, rxPriv := splitTestKeys(t)
	msg, _ := NewPlaintextMessage("a@x", "b@x", "s", "legacy", senderPub)
	sh, content, _ := Split(msg, senderPriv)
	env, err := EncryptSplit(sh, content, []RecipientInfo{{X25519Pub: rxPub}}, senderPriv)
	if err != nil {
		t.Fatal(err)
	}

	noAddr := *env
	noAddr.BodyContentAddress = nil
	if err := noAddr.VerifyBodyContentAddress(); err != nil {
		t.Fatalf("empty address must fail open, got %v", err)
	}

	junk := *env
	junk.BodyContentAddress = []byte{0xde, 0xad}
	if err := junk.VerifyBodyContentAddress(); err != nil {
		t.Fatalf("unrecognized address must fail open, got %v", err)
	}

	var v1 EncryptedEnvelope
	if err := v1.VerifyBodyContentAddress(); err != nil {
		t.Fatalf("non-split envelope must fail open, got %v", err)
	}

	// A header with no committed address skips the bind in DecryptBody.
	h, _ := DecryptHeader(env, rxPriv, rxPub)
	legacy := h.Header
	legacy.BodyContentAddress = nil
	if _, err := DecryptBody(env, &legacy, rxPriv, rxPub); err != nil {
		t.Fatalf("empty-address header must skip the address bind, got %v", err)
	}
}
