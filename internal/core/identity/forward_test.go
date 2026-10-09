package identity

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// An empty forward_to adds no bytes: a record that never set it signs exactly as it did before the
// field existed, so every record already published keeps verifying.
func TestForwardToEmptyIsByteIdentical(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewIdentityRecord("alice@dmcn.email", kp)
	if err != nil {
		t.Fatal(err)
	}
	before, err := rec.signableBytes()
	if err != nil {
		t.Fatal(err)
	}
	rec.ForwardTo = ""
	after, err := rec.signableBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("an empty forward_to changed the signed bytes")
	}
	rec.ForwardTo = "alice@example.org"
	set, err := rec.signableBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, set) {
		t.Fatal("forward_to is not in the signed bytes")
	}
}

// The owner's signature covers forward_to: it survives the wire, and nobody without the owner's key
// can add, change or remove it.
func TestForwardToSignedAndRoundTrips(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewIdentityRecord("alice@dmcn.email", kp)
	if err != nil {
		t.Fatal(err)
	}
	rec.ForwardTo = "alice@example.org"
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	got, err := IdentityRecordFromProto(rec.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	if got.ForwardTo != "alice@example.org" {
		t.Fatalf("ForwardTo = %q after round trip", got.ForwardTo)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, tampered := range []string{"mallory@example.org", ""} {
		pb := rec.ToProto()
		pb.ForwardTo = tampered
		bad, err := IdentityRecordFromProto(pb)
		if err != nil {
			t.Fatal(err)
		}
		if err := bad.Verify(); err == nil {
			t.Fatalf("a record with forward_to changed to %q still verifies", tampered)
		}
	}
}

func TestValidateForwardTo(t *testing.T) {
	const self = "alice@dmcn.email"
	for _, ok := range []string{"", "alice@example.org", "Alice.Smith+dmcn@Example.org", "bob@dmcn.email", "x@localhost"} {
		if err := ValidateForwardTo(self, ok); err != nil {
			t.Errorf("ValidateForwardTo(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{
		self, "ALICE@dmcn.email", // itself
		"alice", "@example.org", "alice@", // not an address
		"Alice <alice@example.org>", "<alice@example.org>", // not bare
		"a@example.org, b@example.org", "alice@example.org\r\nBcc: x@y.z", // more than one, or a header
		strings.Repeat("a", 250) + "@example.org", // too long
	} {
		if err := ValidateForwardTo(self, bad); !errors.Is(err, ErrInvalidForwardTo) {
			t.Errorf("ValidateForwardTo(%q) = %v, want ErrInvalidForwardTo", bad, err)
		}
	}
}

// A malformed forward is refused when the record is parsed, so it never reaches a sender.
func TestIdentityRecordRejectsInvalidForwardTo(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewIdentityRecord("alice@dmcn.email", kp)
	if err != nil {
		t.Fatal(err)
	}
	pb := rec.ToProto()
	pb.ForwardTo = "alice@dmcn.email"
	if _, err := IdentityRecordFromProto(pb); !errors.Is(err, ErrInvalidForwardTo) {
		t.Fatalf("parse with a self-forward = %v, want ErrInvalidForwardTo", err)
	}
}
