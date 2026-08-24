package registry

import (
	"context"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestVerifyRouting exercises the sender-side routing-integrity gate. On a domain with a DAR,
// relay hints must be attested by a verified operator routing credential; a stripped credential
// (attacker-controlled unsigned field-7 hints) or a tampered/forged one is rejected, defeating
// the forged-routing mail-redirection attack. A domain with no DAR is best-effort (no operator
// to attest routing), and empty hints defer to the caller.
func TestVerifyRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	reg, src := makeReg(t)

	const domain = "route.test"
	past := time.Now().Add(-time.Hour)
	root := mustKP(t)
	routeIssuer := mustKP(t) // sub-authority that MAY issue routing

	dar, _ := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	dar.AuthorityEffectiveFrom = past
	c := &identity.Credential{Version: 1, Subject: routeIssuer.Ed25519Public, Domain: domain, Roles: []string{identity.RoleSubAuthority}, Grants: []string{identity.RoleRouting}, IssuedAt: past}
	if err := c.Sign(root); err != nil {
		t.Fatal(err)
	}
	dar.AuthorityCredentials = append(dar.AuthorityCredentials, *c)
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	src.PutDAR(dar)

	hints := []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA", "/ip4/10.0.0.2/tcp/7400/p2p/QmB"}
	newManaged := func(t *testing.T, local string) *identity.IdentityRecord {
		t.Helper()
		kp := mustKP(t)
		rec, _ := identity.NewIdentityRecord(local+"@"+domain, kp)
		if err := rec.Sign(kp); err != nil {
			t.Fatal(err)
		}
		return rec
	}

	t.Run("valid routing credential accepted", func(t *testing.T) {
		rec := newManaged(t, "alice")
		if err := rec.IssueRoutingCredential(routeIssuer, hints, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := reg.VerifyRouting(ctx, rec); err != nil {
			t.Fatalf("valid routing must verify: %v", err)
		}
	})

	t.Run("managed domain with hints but NO routing credential rejected", func(t *testing.T) {
		// The core attack: an attacker republishes the record with unsigned field-7 hints and
		// no routing credential. The owner self-signature still verifies (hints aren't covered),
		// so only this gate stops it.
		rec := newManaged(t, "bob")
		rec.RelayHints = hints // unsigned mirror, no routing credential
		if err := reg.VerifyRouting(ctx, rec); err == nil {
			t.Fatal("unsigned hints on a managed domain must be rejected")
		}
	})

	t.Run("tampered hints rejected", func(t *testing.T) {
		rec := newManaged(t, "carol")
		if err := rec.IssueRoutingCredential(routeIssuer, hints, time.Now()); err != nil {
			t.Fatal(err)
		}
		rec.RelayHints = []string{"/ip4/10.0.0.66/tcp/7400/p2p/QmEvil"} // tamper the mirror
		if err := reg.VerifyRouting(ctx, rec); err == nil {
			t.Fatal("hints disagreeing with the routing credential must be rejected")
		}
	})

	t.Run("empty hints deferred to caller", func(t *testing.T) {
		rec := newManaged(t, "dave") // no hints, no routing credential
		if err := reg.VerifyRouting(ctx, rec); err != nil {
			t.Fatalf("empty hints must return nil (caller handles it): %v", err)
		}
	})

	t.Run("no-DAR domain is best-effort", func(t *testing.T) {
		kp := mustKP(t)
		rec, _ := identity.NewIdentityRecord("eve@open.test", kp) // no DAR registered for open.test
		if err := rec.Sign(kp); err != nil {
			t.Fatal(err)
		}
		rec.RelayHints = hints
		if err := reg.VerifyRouting(ctx, rec); err != nil {
			t.Fatalf("open (no-DAR) domain must be best-effort nil: %v", err)
		}
	})
}
