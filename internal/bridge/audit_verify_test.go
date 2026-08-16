package bridge_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

func writeAuditLog(t *testing.T, path string, kp *identity.IdentityKeyPair, n int) {
	t.Helper()
	al, err := bridge.NewFileAuditLog(path, kp.Ed25519Private, testLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < n; i++ {
		al.Record(bridge.AuditEvent{Action: "inbound.deliver", From: fmt.Sprintf("u%d@gmail.com", i), Success: true})
	}
	if err := al.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestAuditVerifyValidChain(t *testing.T) {
	kp := mustKeyPair(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	writeAuditLog(t, path, kp, 4)

	n, err := bridge.VerifyAuditLog(path, kp.Ed25519Public)
	if err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}
	if n != 4 {
		t.Fatalf("verified %d records, want 4", n)
	}
}

func TestAuditVerifyChainContinuesAcrossReopen(t *testing.T) {
	kp := mustKeyPair(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	writeAuditLog(t, path, kp, 2) // first lifetime
	writeAuditLog(t, path, kp, 1) // reopen: must recover head and continue the chain

	n, err := bridge.VerifyAuditLog(path, kp.Ed25519Public)
	if err != nil {
		t.Fatalf("chain across reopen should verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d, want 3", n)
	}
}

func TestAuditVerifyDetectsEdit(t *testing.T) {
	kp := mustKeyPair(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	writeAuditLog(t, path, kp, 3)

	// Edit a field value in place — the recomputed hash will no longer match.
	raw, _ := os.ReadFile(path)
	edited := bytes.Replace(raw, []byte("u1@gmail.com"), []byte("xx@evil.com"), 1)
	if bytes.Equal(raw, edited) {
		t.Fatal("test setup: edit did not change the file")
	}
	os.WriteFile(path, edited, 0o600)

	if _, err := bridge.VerifyAuditLog(path, kp.Ed25519Public); !errors.Is(err, bridge.ErrAuditTampered) {
		t.Fatalf("expected ErrAuditTampered for an edited record, got %v", err)
	}
}

func TestAuditVerifyDetectsReorderAndDeletion(t *testing.T) {
	kp := mustKeyPair(t)

	for _, tc := range []struct {
		name   string
		mutate func(lines [][]byte) [][]byte
	}{
		{"reorder", func(l [][]byte) [][]byte { l[0], l[1] = l[1], l[0]; return l }},
		{"delete-middle", func(l [][]byte) [][]byte { return append(l[:1], l[2:]...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			writeAuditLog(t, path, kp, 3)
			raw, _ := os.ReadFile(path)
			lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
			lines = tc.mutate(lines)
			os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600)

			if _, err := bridge.VerifyAuditLog(path, kp.Ed25519Public); !errors.Is(err, bridge.ErrAuditTampered) {
				t.Fatalf("expected ErrAuditTampered, got %v", err)
			}
		})
	}
}

// A full rewrite by an attacker WITHOUT the bridge key produces a self-consistent
// chain, but the signatures are made with the wrong key, so verification against
// the real bridge public key fails.
func TestAuditVerifyDetectsForgedRewrite(t *testing.T) {
	realKP := mustKeyPair(t)
	attackerKP := mustKeyPair(t)
	path := filepath.Join(t.TempDir(), "audit.log")

	// Attacker writes a perfectly chained log — but signs with their own key.
	writeAuditLog(t, path, attackerKP, 3)

	if _, err := bridge.VerifyAuditLog(path, realKP.Ed25519Public); !errors.Is(err, bridge.ErrAuditTampered) {
		t.Fatalf("a log signed by the wrong key must fail verification, got %v", err)
	}
	// Sanity: it does verify against the attacker's own key (chain itself is valid).
	if _, err := bridge.VerifyAuditLog(path, attackerKP.Ed25519Public); err != nil {
		t.Fatalf("attacker's own chain should be internally valid: %v", err)
	}
}
