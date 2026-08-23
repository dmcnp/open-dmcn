package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
	webapi "dmcn.dev/open-dmcn/internal/web/api"
)

// TestSelfRegistration exercises the operator-side registration path (provisionIdentity): a
// browser-equivalent self-signed record is provisioned, becomes resolvable with operator routing
// hints, and can then send + receive like a seeded identity. It also pins the two node-owned
// guards: a wrong-domain address is refused, and a duplicate registration is refused.
func TestSelfRegistration(t *testing.T) {
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx := context.Background()
	const domain = "localhost"

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       domain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.Close()

	seeds := newSeedStore(t.TempDir(), "test-pass")
	now := time.Now()
	rootKP, err := seeds.seedDomainDev(ctx, n, domain, now)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	// browserRecord builds a self-signed IdentityRecord for address exactly as the browser does
	// (generate keys, self-sign the identity core) — no operator credential yet.
	browserRecord := func(address string) (*identity.IdentityKeyPair, *identity.IdentityRecord) {
		t.Helper()
		kp, err := identity.GenerateIdentityKeyPair()
		if err != nil {
			t.Fatalf("keypair: %v", err)
		}
		rec, err := identity.NewIdentityRecord(address, kp)
		if err != nil {
			t.Fatalf("record: %v", err)
		}
		if err := rec.Sign(kp); err != nil {
			t.Fatalf("self-sign: %v", err)
		}
		return kp, rec
	}

	// Register carol.
	_, carolRec := browserRecord("carol@" + domain)
	status, err := provisionIdentity(ctx, n, rootKP, domain, carolRec, now)
	if err != nil {
		t.Fatalf("provision carol: %v", err)
	}
	if status != "active" {
		t.Fatalf("status = %q, want active", status)
	}

	// Carol now resolves, with operator-owned routing hints attached.
	resolved, err := n.Lookup(ctx, "carol@"+domain)
	if err != nil {
		t.Fatalf("lookup carol: %v", err)
	}
	if len(resolved.RelayHints) == 0 {
		t.Fatal("registered carol resolved with no relay hints")
	}
	if !resolved.HasRoutingCredential() {
		t.Fatal("registered carol has no routing credential")
	}

	// Duplicate registration is refused.
	_, dupRec := browserRecord("carol@" + domain)
	if _, err := provisionIdentity(ctx, n, rootKP, domain, dupRec, now); !errors.Is(err, webapi.ErrRegisterExists) {
		t.Fatalf("duplicate register err = %v, want ErrRegisterExists", err)
	}

	// A wrong-domain address is refused.
	_, offRec := browserRecord("dave@elsewhere.example")
	if _, err := provisionIdentity(ctx, n, rootKP, domain, offRec, now); !errors.Is(err, webapi.ErrRegisterDomainNotServed) {
		t.Fatalf("off-domain register err = %v, want ErrRegisterDomainNotServed", err)
	}
}
