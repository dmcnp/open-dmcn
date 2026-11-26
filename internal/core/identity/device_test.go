package identity

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func devPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestDeviceApprovalBindings: an approval is a single, specific permission. Each field it binds
// closes a way of reusing it somewhere it was never meant to apply.
func TestDeviceApprovalBindings(t *testing.T) {
	approverPub, approverPriv := devPair(t)
	subject, _ := devPair(t)
	nonce := []byte("nonce-from-this-exchange--------")
	at := time.Unix(1_700_000_000, 0).UTC()
	const addr = "alice@dmcn.email"

	sig, err := SignDeviceApproval(approverPriv, addr, subject, nonce, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceApproval(approverPub, addr, subject, nonce, sig, at); err != nil {
		t.Fatalf("a genuine approval failed to verify: %v", err)
	}

	other, _ := devPair(t)
	tests := []struct {
		name   string
		verify func() error
	}{
		{"replayed on another mailbox", func() error {
			return VerifyDeviceApproval(approverPub, "bob@dmcn.email", subject, nonce, sig, at)
		}},
		{"reused for a different device", func() error {
			return VerifyDeviceApproval(approverPub, addr, other, nonce, sig, at)
		}},
		{"lifted from an earlier exchange", func() error {
			return VerifyDeviceApproval(approverPub, addr, subject, []byte("a-different-challenge-nonce-----"), sig, at)
		}},
		{"attributed to a different approver", func() error {
			return VerifyDeviceApproval(other, addr, subject, nonce, sig, at)
		}},
		{"re-dated to claim more tenure", func() error {
			// The attested time is what a later key rotation measures tenure against, so it has
			// to be inside the signature rather than beside it.
			return VerifyDeviceApproval(approverPub, addr, subject, nonce, sig, at.Add(-90*24*time.Hour))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.verify(); err == nil {
				t.Fatal("approval verified, want refusal")
			}
		})
	}
}

// TestDeviceApprovalAndRetirementAreNotInterchangeable: one signature lets a device in and the
// other cuts one off. A shared context would make each usable as the other, so an approval
// captured from a pairing could be replayed to remove the device that gave it.
func TestDeviceApprovalAndRetirementAreNotInterchangeable(t *testing.T) {
	pub, priv := devPair(t)
	subject, _ := devPair(t)
	nonce := []byte("nonce-from-this-exchange--------")
	at := time.Unix(1_700_000_000, 0).UTC()
	const addr = "alice@dmcn.email"

	approval, err := SignDeviceApproval(priv, addr, subject, nonce, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceRetirement(pub, addr, subject, nonce, approval); err == nil {
		t.Fatal("an approval verified as a retirement")
	}

	retirement, err := SignDeviceRetirement(priv, addr, subject, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceApproval(pub, addr, subject, nonce, retirement, at); err == nil {
		t.Fatal("a retirement verified as an approval")
	}
	if err := VerifyDeviceRetirement(pub, addr, subject, nonce, retirement); err != nil {
		t.Fatalf("a genuine retirement failed to verify: %v", err)
	}
}

// TestDeviceActionAddressIsCaseInsensitive: addresses are compared case-insensitively
// everywhere else, and a signature that depended on the caller's capitalisation would fail for
// reasons no one could diagnose.
func TestDeviceActionAddressIsCaseInsensitive(t *testing.T) {
	pub, priv := devPair(t)
	subject, _ := devPair(t)
	nonce := []byte("nonce-from-this-exchange--------")
	at := time.Unix(1_700_000_000, 0).UTC()

	sig, err := SignDeviceApproval(priv, "Alice@DMCN.email", subject, nonce, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceApproval(pub, "alice@dmcn.email", subject, nonce, sig, at); err != nil {
		t.Fatalf("capitalisation changed the signed bytes: %v", err)
	}
}
