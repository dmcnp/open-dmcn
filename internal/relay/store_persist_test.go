package relay

import (
	"testing"

	leveldbds "github.com/ipfs/go-ds-leveldb"
	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// testEnvelope builds a real encrypted envelope for a fresh recipient.
func testEnvelope(t *testing.T) *message.EncryptedEnvelope {
	t.Helper()
	kp, _ := identity.GenerateIdentityKeyPair()
	msg, _ := message.NewPlaintextMessage("alice@localhost", "bob@localhost", "Subj", "Body", kp.Ed25519Public)
	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(kp.Ed25519Private); err != nil {
		t.Fatalf("sign: %v", err)
	}
	rcpt, _ := identity.GenerateIdentityKeyPair()
	env, err := message.Encrypt(sm, []message.RecipientInfo{{DeviceID: rcpt.DeviceID, X25519Pub: rcpt.X25519Public}})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return env
}

// A durable message store recovers queued envelopes and their delivery status
// after a restart: a pending envelope is still fetchable, and an acked one stays
// delivered (and out of Fetch).
func TestMessageStorePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	log := logr.With(logr.M("test", true))
	const addr = "626f62" // arbitrary recipient key hex

	pendingEnv := testEnvelope(t)
	ackedEnv := testEnvelope(t)
	pendingHash := [32]byte{1, 1, 1}
	ackedHash := [32]byte{2, 2, 2}

	// First lifetime: store two envelopes, deliver one, then "crash" (close ds).
	d1, err := leveldbds.NewDatastore(dir, nil)
	if err != nil {
		t.Fatalf("open ds: %v", err)
	}
	s1, err := NewPersistentMessageStore(d1, log)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	s1.Store(addr, pendingEnv, pendingHash)
	s1.Store(addr, ackedEnv, ackedHash)
	if err := s1.Ack(ackedHash); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := d1.Close(); err != nil {
		t.Fatalf("close ds: %v", err)
	}

	// Second lifetime: reopen the same directory.
	d2, err := leveldbds.NewDatastore(dir, nil)
	if err != nil {
		t.Fatalf("reopen ds: %v", err)
	}
	defer d2.Close()
	s2, err := NewPersistentMessageStore(d2, log)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}

	if c := s2.Count(); c != 2 {
		t.Fatalf("recovered count = %d, want 2", c)
	}
	// The pending envelope survives and is still fetchable.
	envs, hashes := s2.Fetch(addr)
	if len(envs) != 1 || hashes[0] != pendingHash {
		t.Fatalf("fetch after restart = %d envelopes (hashes %v), want 1 pending", len(envs), hashes)
	}
	if envs[0].MessageID != pendingEnv.MessageID {
		t.Fatal("recovered envelope payload does not match the stored one")
	}
	// Delivery status survives too.
	if st, err := s2.DeliveryStatusOf(ackedHash); err != nil || st != Delivered {
		t.Fatalf("acked status after restart = %d (err %v), want Delivered", st, err)
	}
	if st, err := s2.DeliveryStatusOf(pendingHash); err != nil || st != Pending {
		t.Fatalf("pending status after restart = %d (err %v), want Pending", st, err)
	}
}

// In-memory stores (no datastore) keep working unchanged — persist is a no-op.
func TestInMemoryStoreUnaffected(t *testing.T) {
	s := NewMessageStore()
	env := testEnvelope(t)
	h := [32]byte{9}
	s.Store("aa", env, h)
	if c := s.Count(); c != 1 {
		t.Fatalf("count = %d, want 1", c)
	}
	if envs, _ := s.Fetch("aa"); len(envs) != 1 {
		t.Fatalf("fetch = %d, want 1", len(envs))
	}
}
