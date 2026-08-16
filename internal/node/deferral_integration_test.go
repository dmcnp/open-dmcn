package node_test

import (
	"context"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// resolverClient creates a ClientOnly node — no local record store, so every lookup goes through the
// DNS-seeded fleet resolver — with the given static _dmcn map. resolveVia dials the seeds from the
// static config itself, so no bootstrap Peers are needed.
func resolverClient(t *testing.T, ctx context.Context, dns map[string]domainverify.Record) *node.Node {
	t.Helper()
	c, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		ClientOnly:   true,
	})
	if err != nil {
		t.Fatalf("resolver client: %v", err)
	}
	c.SetStaticDNS(dns)
	return c
}

func selfSignedRecord(t *testing.T, address string) *identity.IdentityRecord {
	t.Helper()
	kp := mustKPT(t)
	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		t.Fatalf("new record %s: %v", address, err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatalf("sign record %s: %v", address, err)
	}
	return rec
}

// TestFleetDeferralResolvesWithoutPinning is the opt-in relaxation: a mailbox domain that defers via
// DNS `fleet=` resolves through the fleet's seeds even though (a) the fleet domain's _dmcn carries NO
// fp (seeds only — it hosts no mail of its own yet) and (b) the mailbox domain's DAR declares NO
// `fleet_domain`. The DNS `fleet=` is followed as pure discovery; the DAR still verifies against the
// mailbox domain's own fp.
func TestFleetDeferralResolvesWithoutPinning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const mailboxDomain = "mail.test"
	const fleetDomain = "fleet.test"

	fn := fleetNode(t, ctx)
	defer fn.Close()

	root := mustKPT(t)
	dar := signDAR(t, mailboxDomain, root) // default DAR: no FleetDomain set
	if _, opted := dar.DefersToFleet(); opted {
		t.Fatal("precondition: a default DAR must NOT declare a fleet_domain")
	}
	putDAR(t, ctx, dar, fn)
	putRec(t, ctx, selfSignedRecord(t, "alice@"+mailboxDomain), fn)

	// Mailbox domain defers (fp + fleet=, NO seeds); fleet domain has seeds ONLY (no fp).
	client := resolverClient(t, ctx, map[string]domainverify.Record{
		mailboxDomain: {Fingerprint: dar.Fingerprint(), Fleet: fleetDomain},
		fleetDomain:   {Seeds: []string{seedOf(fn)}},
	})
	defer client.Close()

	got, err := client.Lookup(ctx, "alice@"+mailboxDomain)
	if err != nil {
		t.Fatalf("deferral lookup failed (opt-in relaxation should allow it): %v", err)
	}
	if got.Address != "alice@"+mailboxDomain {
		t.Fatalf("resolved wrong record: %s", got.Address)
	}
}

// TestFleetDeferralPinningRejectsMismatch is the opt-in pinning: when the DAR DOES declare a
// `fleet_domain`, the resolver rejects a DNS `fleet=` that points elsewhere — the defense-in-depth an
// operator gets by setting it (e.g. via `domain register --fleet`).
func TestFleetDeferralPinningRejectsMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const mailboxDomain = "mail.test"

	fn := fleetNode(t, ctx)
	defer fn.Close()

	root := mustKPT(t)
	dar, err := identity.NewDomainAuthorityRecord(mailboxDomain, root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dar.FleetDomain = "good.fleet" // opt into pinning
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	putDAR(t, ctx, dar, fn)
	putRec(t, ctx, selfSignedRecord(t, "alice@"+mailboxDomain), fn)

	// DNS points fleet= at a DIFFERENT domain than the DAR pins; that domain's seeds resolve to the
	// same node, so the dial succeeds and we reach verifyDAR, which must reject on the mismatch.
	client := resolverClient(t, ctx, map[string]domainverify.Record{
		mailboxDomain: {Fingerprint: dar.Fingerprint(), Fleet: "evil.fleet"},
		"evil.fleet":  {Seeds: []string{seedOf(fn)}},
	})
	defer client.Close()

	if _, err := client.Lookup(ctx, "alice@"+mailboxDomain); err == nil {
		t.Fatal("expected fleet deferral mismatch to reject resolution, got success")
	}
}
