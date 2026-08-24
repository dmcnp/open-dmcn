package identity

import (
	"errors"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"
	"google.golang.org/protobuf/proto"
)

func TestGenerateIdentityKeyPair(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair() error: %v", err)
	}

	if len(kp.Ed25519Public) != 32 {
		t.Errorf("Ed25519Public size = %d, want 32", len(kp.Ed25519Public))
	}
	if len(kp.Ed25519Private) != 64 {
		t.Errorf("Ed25519Private size = %d, want 64", len(kp.Ed25519Private))
	}
	if kp.X25519Public == [32]byte{} {
		t.Error("X25519Public is all zeros")
	}
	if kp.X25519Private == [32]byte{} {
		t.Error("X25519Private is all zeros")
	}
	if kp.DeviceID == [16]byte{} {
		t.Error("DeviceID is all zeros")
	}
	if kp.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
}

// Round-trip test — GenerateIdentityKeyPair → Sign IdentityRecord → Verify succeeds.
func TestIdentityRoundTrip(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair(): %v", err)
	}

	rec, err := NewIdentityRecord("alice@example.com", kp)
	if err != nil {
		t.Fatalf("NewIdentityRecord(): %v", err)
	}

	if err := rec.Sign(kp); err != nil {
		t.Fatalf("Sign(): %v", err)
	}

	if err := rec.Verify(); err != nil {
		t.Errorf("Verify() on freshly signed record: %v", err)
	}
}

// Tamper test — mutating any field of a signed IdentityRecord causes Verify to return an error.
func TestIdentityTamper(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("bob@example.com", kp)
	rec.Sign(kp)

	tests := []struct {
		name   string
		tamper func(r *IdentityRecord)
	}{
		{"address", func(r *IdentityRecord) { r.Address = "eve@example.com" }},
		{"version", func(r *IdentityRecord) { r.Version = 99 }},
		{"public key byte", func(r *IdentityRecord) { r.Ed25519Public[0] ^= 0xff }},
		{"x25519 public key", func(r *IdentityRecord) { r.X25519Public[0] ^= 0xff }},
		{"created_at", func(r *IdentityRecord) { r.CreatedAt = r.CreatedAt.Add(time.Hour) }},
		{"expires_at", func(r *IdentityRecord) { r.ExpiresAt = time.Now().Add(24 * time.Hour) }},
		// relay_hints is intentionally NOT covered by the owner self-signature — it is
		// operator-owned (carried in the routing credential). See TestRoutingCredential*.
		{"verification_tier", func(r *IdentityRecord) { r.VerificationTier = TierDANE }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clone the record
			tampered := *rec
			tampered.Ed25519Public = make([]byte, len(rec.Ed25519Public))
			copy(tampered.Ed25519Public, rec.Ed25519Public)
			tampered.RelayHints = append([]string{}, rec.RelayHints...)

			tt.tamper(&tampered)

			if err := tampered.Verify(); err == nil {
				t.Errorf("Verify() should fail after tampering %s", tt.name)
			}
		})
	}
}

// TestIssueCredentialPreservesSelfSignature locks the invariant the web registration
// flow depends on: attaching the domain's operator-owned credentials (AddressCredential
// and RoutingCredential) must NOT invalidate the owner self-signature, and must NOT
// change the owner-signed VerificationTier. The effective (verified) tier is derived
// reader-side from the AddressCredential (registry.VerifyManagedIdentity), never by
// mutating the self-signed field.
//
// Regression: a web address-issuer hook raised VerificationTier to TierDomainDNS after
// the client had self-signed at TierUnverified — because that field is covered by the
// owner self-signature (see TestIdentityTamper/"verification_tier"), registry.Register's
// re-Verify() then failed and every managed-domain registration broke.
func TestIssueCredentialPreservesSelfSignature(t *testing.T) {
	owner, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewIdentityRecord("alice@example.com", owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(owner); err != nil {
		t.Fatal(err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("baseline: owner self-signature must verify: %v", err)
	}
	if rec.VerificationTier != TierUnverified {
		t.Fatalf("a freshly self-signed record must be at TierUnverified, got %v", rec.VerificationTier)
	}

	// The operator (a separate key) attests the address + routing. Neither is covered by
	// the owner self-signature, so both must leave rec.Verify() intact.
	issuer, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.IssueAddressCredential(issuer, time.Now()); err != nil {
		t.Fatalf("IssueAddressCredential: %v", err)
	}
	if !rec.HasAddressCredential() {
		t.Fatal("expected an address credential to be attached")
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("owner self-signature must remain valid after issuing an AddressCredential: %v", err)
	}
	if rec.VerificationTier != TierUnverified {
		t.Fatalf("issuing an AddressCredential must not change the owner-signed VerificationTier, got %v", rec.VerificationTier)
	}

	if err := rec.IssueRoutingCredential(issuer, []string{"/ip4/127.0.0.1/tcp/7401"}, time.Now()); err != nil {
		t.Fatalf("IssueRoutingCredential: %v", err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("owner self-signature must remain valid after issuing a RoutingCredential: %v", err)
	}
	if rec.VerificationTier != TierUnverified {
		t.Fatalf("issuing a RoutingCredential must not change the owner-signed VerificationTier, got %v", rec.VerificationTier)
	}
}

// Fingerprint test — returns 40-char uppercase hex; different key pairs produce
// different fingerprints.
func TestFingerprint(t *testing.T) {
	kp1, _ := GenerateIdentityKeyPair()
	kp2, _ := GenerateIdentityKeyPair()

	rec1, _ := NewIdentityRecord("alice@example.com", kp1)
	rec2, _ := NewIdentityRecord("bob@example.com", kp2)

	fp1 := rec1.Fingerprint()
	fp2 := rec2.Fingerprint()

	// Must be 40 characters
	if len(fp1) != 40 {
		t.Errorf("fingerprint length = %d, want 40", len(fp1))
	}

	// Must be uppercase hex
	for _, c := range fp1 {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			t.Errorf("fingerprint contains non-uppercase-hex character: %c", c)
			break
		}
	}

	// Different key pairs must produce different fingerprints
	if fp1 == fp2 {
		t.Error("different key pairs produced same fingerprint")
	}

	// Same key pair must produce same fingerprint
	fp1Again := rec1.Fingerprint()
	if fp1 != fp1Again {
		t.Error("same record produced different fingerprints")
	}
}

func TestNewIdentityRecordInvalidAddress(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()

	invalid := []string{"", "noatsign", "@", "a@", "@b", "@@"}
	for _, addr := range invalid {
		_, err := NewIdentityRecord(addr, kp)
		if err == nil {
			t.Errorf("NewIdentityRecord(%q) should fail", addr)
		}
	}
}

func TestIdentityRecordProtoRoundTrip(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", kp)
	rec.RelayHints = []string{"relay1.example.com", "relay2.example.com"}
	rec.ExpiresAt = time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second)
	rec.Sign(kp)

	// Convert to proto
	pb := rec.ToProto()

	// Serialize and deserialize
	data, err := proto.Marshal(pb)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	pb2 := &dmcnpb.IdentityRecord{}
	if err := proto.Unmarshal(data, pb2); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	// Convert back
	rec2, err := IdentityRecordFromProto(pb2)
	if err != nil {
		t.Fatalf("IdentityRecordFromProto: %v", err)
	}

	// Signature should still verify
	if err := rec2.Verify(); err != nil {
		t.Errorf("Verify() after proto round-trip: %v", err)
	}

	// Fingerprints should match
	if rec.Fingerprint() != rec2.Fingerprint() {
		t.Error("fingerprints differ after proto round-trip")
	}
}

func TestIdentityRecordFromProtoNil(t *testing.T) {
	_, err := IdentityRecordFromProto(nil)
	if err == nil {
		t.Error("IdentityRecordFromProto(nil) should fail")
	}
}

func TestSignWithInvalidKey(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", kp)

	// Create a key pair with an invalid private key length
	badKP := &IdentityKeyPair{
		Ed25519Private: []byte("short"), // invalid size
	}

	err := rec.Sign(badKP)
	if err == nil {
		t.Error("Sign() with invalid key should fail")
	}
}

func TestVerifyWithCorruptedPublicKey(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", kp)
	rec.Sign(kp)

	// Set public key to invalid length
	rec.Ed25519Public = []byte("short")
	if err := rec.Verify(); err == nil {
		t.Error("Verify() with short public key should fail")
	}
}

func TestIdentityRecordWithRelayHintsAndExpiry(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", kp)
	rec.RelayHints = []string{"relay1.example.com", "relay2.example.com"}
	rec.VerificationTier = TierDomainDNS
	rec.ExpiresAt = time.Now().Add(365 * 24 * time.Hour).UTC()

	if err := rec.Sign(kp); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := rec.Verify(); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestIdentityRecordFromProtoNoExpiry(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", kp)
	rec.Sign(kp)

	pb := rec.ToProto()
	pb.ExpiresAt = 0 // no expiry

	rec2, err := IdentityRecordFromProto(pb)
	if err != nil {
		t.Fatalf("IdentityRecordFromProto: %v", err)
	}
	if !rec2.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be zero when pb.ExpiresAt is 0")
	}
}

func TestSignMarshalFailure(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", kp)

	old := protoMarshal
	protoMarshal = func(m proto.Message) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	defer func() { protoMarshal = old }()

	if err := rec.Sign(kp); err == nil {
		t.Error("Sign() should fail when marshal fails")
	}
}

func TestVerifyMarshalFailure(t *testing.T) {
	kp, _ := GenerateIdentityKeyPair()
	rec, _ := NewIdentityRecord("alice@example.com", kp)

	// Sign with real marshaler first
	rec.Sign(kp)

	// Then break the marshaler
	old := protoMarshal
	protoMarshal = func(m proto.Message) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	defer func() { protoMarshal = old }()

	if err := rec.Verify(); err == nil {
		t.Error("Verify() should fail when marshal fails")
	}
}

func TestVerificationTierValues(t *testing.T) {
	if TierUnverified != 0 {
		t.Errorf("TierUnverified = %d, want 0", TierUnverified)
	}
	// Value 1 is reserved (was TierProviderHosted — removed).
	if TierDomainDNS != 2 {
		t.Errorf("TierDomainDNS = %d, want 2", TierDomainDNS)
	}
	if TierDANE != 3 {
		t.Errorf("TierDANE = %d, want 3", TierDANE)
	}
}
