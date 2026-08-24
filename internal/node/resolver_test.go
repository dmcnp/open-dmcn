package node

import (
	"context"
	"fmt"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

func mustKP(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	return kp
}

// TestResolveViaFleetDeferral runs the full resolution path: a mailbox domain
// (dmcn.email) that runs no nodes and defers to a fleet domain (dmcnmail.com), whose seed serves
// the signed DAR + IdentityRecord. It exercises DNS discovery → deferral → dial → fetch → verify,
// including the signed-fleet_domain == DNS-fleet= enforcement.
func TestResolveViaFleetDeferral(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// dmcn.email domain authority, deferring hosting to dmcnmail.com.
	root := mustKP(t)
	dar, err := identity.NewDomainAuthorityRecord("dmcn.email", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dar.FleetDomain = "dmcnmail.com"
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}

	// alice@dmcn.email — self-signed (uncredentialed ⇒ self-claimed tier).
	aliceKP := mustKP(t)
	alice, err := identity.NewIdentityRecord("alice@dmcn.email", aliceKP)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Sign(aliceKP); err != nil {
		t.Fatal(err)
	}

	// Serving (mailbox) node = part of the dmcnmail.com fleet, authoritative for dmcn.email.
	server, err := New(ctx, Config{
		AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0",
		DataDir: t.TempDir(), Mailbox: true,
	})
	if err != nil {
		t.Fatalf("server node: %v", err)
	}
	defer server.Close()
	if server.Records() == nil {
		t.Fatal("mailbox node has no record store")
	}
	if err := server.Records().PutDAR(ctx, dar); err != nil {
		t.Fatal(err)
	}
	if err := server.Records().PutIdentity(ctx, alice); err != nil {
		t.Fatal(err)
	}

	// Pure client that resolves.
	client, err := New(ctx, Config{
		AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0", ClientOnly: true,
	})
	if err != nil {
		t.Fatalf("client node: %v", err)
	}
	defer client.Close()

	seed := fmt.Sprintf("%s/p2p/%s", server.Host().Addrs()[0], server.Host().ID())

	// Fake DNS: dmcn.email → fingerprint + fleet deferral; dmcnmail.com → seed endpoint.
	restore := setDNS(func(_ context.Context, domain string) (*domainverify.Record, error) {
		switch domain {
		case "dmcn.email":
			return &domainverify.Record{Fingerprint: dar.Fingerprint(), Fleet: "dmcnmail.com"}, nil
		case "dmcnmail.com":
			return &domainverify.Record{Fingerprint: "FLEETFPUNUSED", Seeds: []string{seed}}, nil
		}
		return nil, domainverify.ErrNoRecord
	})
	defer restore()

	got, err := client.Resolve(ctx, "alice@dmcn.email")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Address != "alice@dmcn.email" || got.Verify() != nil {
		t.Fatalf("resolved wrong/invalid record: addr=%s verify=%v", got.Address, got.Verify())
	}

	// Not-found is authoritative once the DAR verifies.
	if _, err := client.Resolve(ctx, "nobody@dmcn.email"); err == nil {
		t.Fatal("expected not-found for an unknown address")
	}
}

// TestLookupViaStaticDNS validates the read path end-to-end: with a static _dmcn config (no real
// DNS), n.Lookup resolves an address purely via the fleet resolver.
func TestLookupViaStaticDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	root := mustKP(t)
	dar, err := identity.NewDomainAuthorityRecord("acme.example", root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	aliceKP := mustKP(t)
	alice, _ := identity.NewIdentityRecord("alice@acme.example", aliceKP)
	if err := alice.Sign(aliceKP); err != nil {
		t.Fatal(err)
	}

	server, err := New(ctx, Config{AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0", DataDir: t.TempDir(), Mailbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = server.Records().PutDAR(ctx, dar)
	_ = server.Records().PutIdentity(ctx, alice)

	seed := fmt.Sprintf("%s/p2p/%s", server.Host().Addrs()[0], server.Host().ID())
	// The domain hosts its own nodes (no fleet deferral): fingerprint + seed in one record.
	staticDNS := map[string]domainverify.Record{
		"acme.example": {Fingerprint: dar.Fingerprint(), Seeds: []string{seed}},
	}
	client, err := New(ctx, Config{
		AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0", ClientOnly: true,
		StaticDNS: staticDNS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The client holds no records of its own, so a successful Lookup proves the resolver served it.
	got, err := client.Lookup(ctx, "alice@acme.example")
	if err != nil {
		t.Fatalf("Lookup via resolver: %v", err)
	}
	if got.Address != "alice@acme.example" || got.Verify() != nil {
		t.Fatalf("resolved wrong/invalid record: %s", got.Address)
	}

	// ResolveDAR (the DAR read path) also works from static DNS.
	rdar, err := client.ResolveDAR(ctx, "acme.example")
	if err != nil || rdar.Domain != "acme.example" {
		t.Fatalf("ResolveDAR = (%v, %v)", rdar, err)
	}
}

// TestResolveRejectsFingerprintMismatch: a fleet that serves a DAR whose fingerprint doesn't match
// the mailbox domain's DNS anchor is rejected — this is the property that makes a hostile fleet
// DoS-only, never a forgery vector.
func TestResolveRejectsFingerprintMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	root := mustKP(t)
	dar, _ := identity.NewDomainAuthorityRecord("dmcn.email", root, time.Now())
	_ = dar.Sign(root)
	aliceKP := mustKP(t)
	alice, _ := identity.NewIdentityRecord("alice@dmcn.email", aliceKP)
	_ = alice.Sign(aliceKP)

	server, err := New(ctx, Config{AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0", DataDir: t.TempDir(), Mailbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = server.Records().PutDAR(ctx, dar)
	_ = server.Records().PutIdentity(ctx, alice)

	client, err := New(ctx, Config{AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0", ClientOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	seed := fmt.Sprintf("%s/p2p/%s", server.Host().Addrs()[0], server.Host().ID())
	restore := setDNS(func(_ context.Context, domain string) (*domainverify.Record, error) {
		// DNS advertises a fingerprint that does NOT match the served DAR (a forged/hostile fleet).
		if domain == "dmcn.email" {
			return &domainverify.Record{Fingerprint: "0000000000000000000000000000000000000000", Seeds: []string{seed}}, nil
		}
		return nil, domainverify.ErrNoRecord
	})
	defer restore()

	if _, err := client.Resolve(ctx, "alice@dmcn.email"); err == nil {
		t.Fatal("expected resolution to fail when the DAR fingerprint != DNS anchor")
	}
}

// setDNS swaps the resolver's DNS hook and returns a restore func.
func setDNS(fn func(context.Context, string) (*domainverify.Record, error)) func() {
	old := resolveDNS
	resolveDNS = fn
	return func() { resolveDNS = old }
}
