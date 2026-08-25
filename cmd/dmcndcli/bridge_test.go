package main

import (
	"crypto/ed25519"
	"strings"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestPubKeyFromPeerIDRoundTrips pins the property both `bridge issue` and `bridge verify-audit`
// rest on: the Ed25519 key recovered from a peer ID is EXACTLY the peer's signing key.
//
// It matters most for verify-audit. That command's whole claim is that the key checking the
// signatures came from somewhere the log cannot influence — the peer ID, which is public and
// published in the domain's _dmcn record. If this recovery were ever wrong, the command would
// either reject good logs or, far worse, verify against a key nobody controls while printing
// the reassuring line.
func TestPubKeyFromPeerIDRoundTrips(t *testing.T) {
	kp := testRoot(t)

	pk, err := libp2pcrypto.UnmarshalEd25519PublicKey(kp.Ed25519Public)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	got, err := pubKeyFromPeerID(id.String())
	if err != nil {
		t.Fatalf("recovering the key from %s: %v", id, err)
	}
	if !ed25519.PublicKey(kp.Ed25519Public).Equal(got) {
		t.Fatal("recovered key differs from the peer's own signing key — signatures would be " +
			"checked against the wrong key")
	}
}

// TestPubKeyFromPeerIDRejectsGarbage keeps a malformed ID an explicit failure. Returning a zero
// key instead would be the dangerous shape: verification against an all-zero key must never be
// mistaken for verification.
func TestPubKeyFromPeerIDRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not-a-peer-id", "12D3KooWtruncated"} {
		if _, err := pubKeyFromPeerID(bad); err == nil {
			t.Errorf("pubKeyFromPeerID(%q) = nil error, want a rejection", bad)
		}
	}
}

// TestVerifyAuditRequiresALog checks the one argument the command cannot default, and that the
// error names the way most people will have obtained the file.
func TestVerifyAuditRequiresALog(t *testing.T) {
	err := cmdBridgeVerifyAudit(nil)
	if err == nil {
		t.Fatal("verify-audit with no --log succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "--log is required") {
		t.Errorf("error = %q, want it to name --log", err)
	}
}
