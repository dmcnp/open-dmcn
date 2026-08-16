package onion

import (
	"bytes"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

func mustKeyPair(t *testing.T) (pub, priv [32]byte) {
	t.Helper()
	pub, priv, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func TestSealOpenRoundTrip(t *testing.T) {
	pub, priv := mustKeyPair(t)
	plaintext := []byte("next_hop=DELIVER|inner payload bytes")

	sl, err := SealLayer(pub, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenLayer(priv, sl)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	pub, _ := mustKeyPair(t)
	_, otherPriv := mustKeyPair(t)
	sl, err := SealLayer(pub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLayer(otherPriv, sl); err == nil {
		t.Fatal("opening with the wrong relay key must fail")
	}
}

func TestOpenTamperedFails(t *testing.T) {
	pub, priv := mustKeyPair(t)
	sl, err := SealLayer(pub, []byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("ciphertext", func(t *testing.T) {
		bad := *sl
		bad.Ciphertext = append([]byte(nil), sl.Ciphertext...)
		bad.Ciphertext[0] ^= 1
		if _, err := OpenLayer(priv, &bad); err == nil {
			t.Fatal("tampered ciphertext must fail the AEAD tag")
		}
	})
	t.Run("ephemeral", func(t *testing.T) {
		bad := *sl
		bad.EphemeralXPub[0] ^= 1
		if _, err := OpenLayer(priv, &bad); err == nil {
			t.Fatal("tampered ephemeral key must fail")
		}
	})
}

// Each seal uses a fresh ephemeral key, so two seals of the same plaintext to
// the same relay are unlinkable (different ephemeral pub + ciphertext).
func TestSealUsesFreshEphemeral(t *testing.T) {
	pub, _ := mustKeyPair(t)
	a, err := SealLayer(pub, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealLayer(pub, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if a.EphemeralXPub == b.EphemeralXPub {
		t.Fatal("ephemeral key must be fresh per seal")
	}
}
