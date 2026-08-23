package petition

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

func newTestStore(t *testing.T, ttl time.Duration) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "petitions.json"), ttl)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// mkPetitioner returns a keypair and a valid possession proof over it, i.e. what a browser sends.
func mkPetitioner(t *testing.T) (*identity.IdentityKeyPair, []byte) {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sig := ed25519.Sign(kp.Ed25519Private, SignableBytes(kp.Ed25519Public, kp.X25519Public))
	return kp, sig
}

func mkCreds(t *testing.T, root, subject *identity.IdentityKeyPair, address string) (*identity.Credential, *identity.Credential) {
	t.Helper()
	rec, err := identity.NewIdentityRecord(address, subject)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	now := time.Now()
	if err := rec.IssueAddressCredential(root, now); err != nil {
		t.Fatalf("address credential: %v", err)
	}
	if err := rec.IssueRoutingCredential(root, []string{"/ip4/127.0.0.1/tcp/1/p2p/x"}, now); err != nil {
		t.Fatalf("routing credential: %v", err)
	}
	return rec.AddressCredential, rec.RoutingCredential
}

// TestCreateRequiresProof is the gate on the public endpoint: a petition is a claim to hold a
// keypair, and without the proof anyone could file one naming someone else's public key and let
// an admin bind an address to a key the petitioner cannot use.
func TestCreateRequiresProof(t *testing.T) {
	s := newTestStore(t, 0)
	kp, sig := mkPetitioner(t)
	other, _ := mkPetitioner(t)

	if _, err := s.Create(kp.Ed25519Public, kp.X25519Public, nil, time.Now()); !errors.Is(err, ErrBadProof) {
		t.Errorf("no signature accepted: %v", err)
	}
	if _, err := s.Create(other.Ed25519Public, other.X25519Public, sig, time.Now()); !errors.Is(err, ErrBadProof) {
		t.Errorf("signature from a different key accepted: %v", err)
	}
	// The X25519 key is inside the signed bytes, so swapping it must break the proof — mail is
	// sealed to that key, so a swap decides who can read the mailbox.
	if _, err := s.Create(kp.Ed25519Public, other.X25519Public, sig, time.Now()); !errors.Is(err, ErrBadProof) {
		t.Errorf("swapped X25519 key accepted: %v", err)
	}
	if _, err := s.Create(kp.Ed25519Public, kp.X25519Public, sig, time.Now()); err != nil {
		t.Errorf("valid petition refused: %v", err)
	}
}

// TestCodeFormatAndUniqueness pins the shape people read aloud, and that codes do not repeat — a
// collision would hand the admin the wrong petition to assign an address to.
func TestCodeFormatAndUniqueness(t *testing.T) {
	s := newTestStore(t, 0)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		kp, sig := mkPetitioner(t)
		p, err := s.Create(kp.Ed25519Public, kp.X25519Public, sig, time.Now())
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if len(p.Code) != 14 || p.Code[4] != '-' || p.Code[9] != '-' {
			t.Fatalf("code %q is not the 0000-0000-0000 shape", p.Code)
		}
		if seen[p.Code] {
			t.Fatalf("duplicate code %q", p.Code)
		}
		seen[p.Code] = true
	}
}

// TestExpiry covers the property that makes the whole design safe to leave unattended: an
// unclaimed petition simply goes away, so the admin never has a queue to triage.
func TestExpiry(t *testing.T) {
	s := newTestStore(t, time.Hour)
	kp, sig := mkPetitioner(t)
	now := time.Now()
	p, err := s.Create(kp.Ed25519Public, kp.X25519Public, sig, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := s.Get(p.Code, now.Add(59*time.Minute)); err != nil {
		t.Errorf("petition gone before its TTL: %v", err)
	}
	if _, err := s.Get(p.Code, now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired petition still readable: %v", err)
	}
	if n := s.Pending(now.Add(2 * time.Hour)); n != 0 {
		t.Errorf("expired petition still queued (%d pending)", n)
	}
}

// TestAssignIsOnce is the anti-redirect rule. A code is spoken aloud and may be overheard; once
// it has been spent, whoever learns it later must not be able to re-point the address.
func TestAssignIsOnce(t *testing.T) {
	s := newTestStore(t, 0)
	root, _ := mkPetitioner(t)
	kp, sig := mkPetitioner(t)
	now := time.Now()
	p, err := s.Create(kp.Ed25519Public, kp.X25519Public, sig, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ac, rc := mkCreds(t, root, kp, "alice@mesh.example")

	if _, err := s.Assign(p.Code, "alice@mesh.example", ac, rc, now); err != nil {
		t.Fatalf("first assign: %v", err)
	}
	if _, err := s.Assign(p.Code, "mallory@mesh.example", ac, rc, now); !errors.Is(err, ErrAssigned) {
		t.Errorf("second assign was allowed to re-point the address: %v", err)
	}
	got, err := s.Get(p.Code, now)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Address != "alice@mesh.example" {
		t.Errorf("address is now %q — the second assign took effect", got.Address)
	}
}

// TestAssignRejectsExpired stops a code being redeemed after its window, which is the only thing
// bounding how long an overheard code stays valuable.
func TestAssignRejectsExpired(t *testing.T) {
	s := newTestStore(t, time.Hour)
	root, _ := mkPetitioner(t)
	kp, sig := mkPetitioner(t)
	now := time.Now()
	p, _ := s.Create(kp.Ed25519Public, kp.X25519Public, sig, now)
	ac, rc := mkCreds(t, root, kp, "alice@mesh.example")

	if _, err := s.Assign(p.Code, "alice@mesh.example", ac, rc, now.Add(2*time.Hour)); err == nil {
		t.Error("an expired petition was assigned an address")
	}
}

// TestPersistenceSurvivesRestart matters because assignment and completion are separated by a
// human conversation: the admin may assign hours before the petitioner reopens their browser, and
// a daemon restart in between must not lose the root's signature.
func TestPersistenceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "petitions.json")
	root, _ := mkPetitioner(t)
	kp, sig := mkPetitioner(t)
	now := time.Now()

	s1, err := NewStore(path, time.Hour)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	p, err := s1.Create(kp.Ed25519Public, kp.X25519Public, sig, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ac, rc := mkCreds(t, root, kp, "alice@mesh.example")
	if _, err := s1.Assign(p.Code, "alice@mesh.example", ac, rc, now); err != nil {
		t.Fatalf("assign: %v", err)
	}

	s2, err := NewStore(path, time.Hour)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.Get(p.Code, now)
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if got.Address != "alice@mesh.example" {
		t.Errorf("address lost across restart: %q", got.Address)
	}
	if got.AddressCredential == nil || got.RoutingCredential == nil {
		t.Fatal("credentials lost across restart — the petitioner could never complete")
	}
	if err := got.AddressCredential.VerifySignature(); err != nil {
		t.Errorf("address credential no longer verifies after a round trip: %v", err)
	}
	if !got.Ed25519Public.Equal(kp.Ed25519Public) {
		t.Error("public key changed across restart")
	}
	if got.X25519Public != kp.X25519Public {
		t.Error("X25519 key changed across restart")
	}
}

// TestCompleteRemoves keeps the queue from doubling as a user directory: once the record is
// published, the published record is the only record.
func TestCompleteRemoves(t *testing.T) {
	s := newTestStore(t, 0)
	kp, sig := mkPetitioner(t)
	now := time.Now()
	p, _ := s.Create(kp.Ed25519Public, kp.X25519Public, sig, now)

	if err := s.Complete(p.Code); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if _, err := s.Get(p.Code, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("completed petition still in the queue: %v", err)
	}
	if err := s.Complete(p.Code); !errors.Is(err, ErrNotFound) {
		t.Errorf("completing twice did not report not-found: %v", err)
	}
}

// TestQueueCap bounds what an unauthenticated flood can cost. Rate limiting caps the rate; this
// caps the total.
func TestQueueCap(t *testing.T) {
	s := newTestStore(t, time.Hour)
	now := time.Now()
	for i := 0; i < maxPending; i++ {
		kp, sig := mkPetitioner(t)
		if _, err := s.Create(kp.Ed25519Public, kp.X25519Public, sig, now); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	kp, sig := mkPetitioner(t)
	if _, err := s.Create(kp.Ed25519Public, kp.X25519Public, sig, now); !errors.Is(err, ErrQueueFull) {
		t.Errorf("queue accepted more than %d pending: %v", maxPending, err)
	}
	// The cap must not be permanent: once the flood ages out, the queue works again.
	if _, err := s.Create(kp.Ed25519Public, kp.X25519Public, sig, now.Add(2*time.Hour)); err != nil {
		t.Errorf("queue still full after everything expired: %v", err)
	}
}
