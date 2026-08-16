package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

func TestKeystoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	ks := New(path, "test-passphrase")

	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Store
	if err := ks.Store("alice@localhost", kp); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Load
	loaded, err := ks.Load("alice@localhost")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Compare fields
	if string(loaded.Ed25519Public) != string(kp.Ed25519Public) {
		t.Error("Ed25519Public mismatch")
	}
	if string(loaded.Ed25519Private) != string(kp.Ed25519Private) {
		t.Error("Ed25519Private mismatch")
	}
	if loaded.X25519Public != kp.X25519Public {
		t.Error("X25519Public mismatch")
	}
	if loaded.X25519Private != kp.X25519Private {
		t.Error("X25519Private mismatch")
	}
	if loaded.DeviceID != kp.DeviceID {
		t.Error("DeviceID mismatch")
	}
	if loaded.CreatedAt.Unix() != kp.CreatedAt.Unix() {
		t.Errorf("CreatedAt = %v, want %v", loaded.CreatedAt, kp.CreatedAt)
	}
}

func TestKeystoreMultipleIdentities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	ks := New(path, "test-passphrase")

	kp1, _ := identity.GenerateIdentityKeyPair()
	kp2, _ := identity.GenerateIdentityKeyPair()

	ks.Store("alice@localhost", kp1)
	ks.Store("bob@localhost", kp2)

	// Load both
	l1, err := ks.Load("alice@localhost")
	if err != nil {
		t.Fatalf("load alice: %v", err)
	}
	l2, err := ks.Load("bob@localhost")
	if err != nil {
		t.Fatalf("load bob: %v", err)
	}

	if l1.DeviceID == l2.DeviceID {
		t.Error("different identities should have different device IDs")
	}
}

func TestKeystoreList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	ks := New(path, "test-passphrase")

	// Empty list
	addrs, err := ks.List()
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(addrs) != 0 {
		t.Errorf("expected empty list, got %d", len(addrs))
	}

	kp, _ := identity.GenerateIdentityKeyPair()
	ks.Store("alice@localhost", kp)
	ks.Store("bob@localhost", kp)

	addrs, err = ks.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(addrs) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(addrs))
	}
}

func TestKeystoreWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	ks1 := New(path, "correct-passphrase")
	kp, _ := identity.GenerateIdentityKeyPair()
	ks1.Store("alice@localhost", kp)

	ks2 := New(path, "wrong-passphrase")
	_, err := ks2.Load("alice@localhost")
	if err == nil {
		t.Fatal("load with wrong passphrase should fail")
	}
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestKeystoreNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	ks := New(path, "test-passphrase")
	kp, _ := identity.GenerateIdentityKeyPair()
	ks.Store("alice@localhost", kp)

	_, err := ks.Load("nonexistent@localhost")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestKeystoreNoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.enc")

	ks := New(path, "test-passphrase")

	_, err := ks.Load("alice@localhost")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestKeystoreOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	ks := New(path, "test-passphrase")

	kp1, _ := identity.GenerateIdentityKeyPair()
	kp2, _ := identity.GenerateIdentityKeyPair()

	ks.Store("alice@localhost", kp1)
	ks.Store("alice@localhost", kp2) // overwrite

	loaded, err := ks.Load("alice@localhost")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Should have kp2's keys, not kp1's
	if loaded.DeviceID != kp2.DeviceID {
		t.Error("overwrite should replace with new key pair")
	}
}

func TestKeystoreInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	// Write garbage
	os.WriteFile(path, []byte("not valid json"), 0600)

	ks := New(path, "test-passphrase")
	_, err := ks.Load("alice@localhost")
	if err == nil {
		t.Fatal("load from invalid file should fail")
	}
}

func TestKeystoreFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.enc")

	ks := New(path, "test-passphrase")
	kp, _ := identity.GenerateIdentityKeyPair()
	ks.Store("alice@localhost", kp)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}
