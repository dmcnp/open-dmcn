package main

import (
	"path/filepath"
	"strings"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/keystore"
)

func TestDmcnTXT(t *testing.T) {
	got := dmcnTXT("mesh.example", "ABC123", []string{"/ip4/1.2.3.4/tcp/7400/p2p/xyz"})
	want := `_dmcn.mesh.example.  TXT  "dmcn-verification=v1; fp=ABC123; seed=/ip4/1.2.3.4/tcp/7400/p2p/xyz"`
	if got != want {
		t.Fatalf("dmcnTXT =\n  %s\nwant\n  %s", got, want)
	}
	// No seeds → just the fingerprint.
	if s := dmcnTXT("d", "FP", nil); s != `_dmcn.d.  TXT  "dmcn-verification=v1; fp=FP"` {
		t.Fatalf("no-seed form = %s", s)
	}
}

// domainFingerprint must reproduce EXACTLY the DAR fingerprint the daemon derives from the same
// seed keystore + root-key alias — otherwise the published _dmcn TXT would not match the daemon's
// DAR and resolution would fail. This pins the shared alias/path convention with cmd/dmcnd/seed.go.
func TestDomainFingerprintMatchesDaemonAnchor(t *testing.T) {
	const domain = "mesh.example"
	const pass = "test-pass"
	dir := t.TempDir()

	// Seed a root key exactly as cmd/dmcnd/seed.go does (alias "__domain_root__@<domain>").
	root, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New(filepath.Join(dir, "seed-keystore.json"), pass)
	if err := ks.Store("__domain_root__@"+domain, root); err != nil {
		t.Fatalf("store root key: %v", err)
	}

	// The CLI's fingerprint...
	got, err := domainFingerprint(dir, pass, domain)
	if err != nil {
		t.Fatalf("domainFingerprint: %v", err)
	}
	// ...must equal the DAR fingerprint the daemon computes from the same root key.
	dar, err := identity.NewDomainAuthorityRecord(domain, root, root.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got != dar.Fingerprint() {
		t.Fatalf("CLI fingerprint %s != daemon DAR fingerprint %s", got, dar.Fingerprint())
	}
	if !strings.Contains(dmcnTXT(domain, got, nil), got) {
		t.Fatal("TXT record does not carry the fingerprint")
	}

	// A wrong passphrase must fail cleanly (not silently emit a bogus anchor).
	if _, err := domainFingerprint(dir, "wrong", domain); err == nil {
		t.Fatal("expected an error loading the root key with the wrong passphrase")
	}
}
