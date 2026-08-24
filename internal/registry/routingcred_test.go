package registry

import (
	"context"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestRoutingCredentialManagedIdentity exercises the operator-owned routing path: a record
// whose RelayHints are carried in a domain-issued routing Credential (role "routing", from
// a Grants:["routing"] sub-authority) verifies; an issuer lacking the routing grant, a
// subject/domain mismatch, or RelayHints that disagree with the credential are rejected.
// Crucially it also shows an OPERATOR re-pointing RelayHints WITHOUT the mailbox owner's
// key (the owner self-signature is untouched).
func TestRoutingCredentialManagedIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	reg, src := makeReg(t)

	const domain = "route.test"
	past := time.Now().Add(-time.Hour)
	root := mustKP(t)
	routeIssuer := mustKP(t) // sub-authority that MAY issue routing
	noGrant := mustKP(t)     // sub-authority that may NOT

	dar, _ := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	dar.AuthorityEffectiveFrom = past
	for _, a := range []struct {
		kp     *identity.IdentityKeyPair
		grants []string
	}{{routeIssuer, []string{identity.RoleRouting}}, {noGrant, nil}} {
		c := &identity.Credential{Version: 1, Subject: a.kp.Ed25519Public, Domain: domain, Roles: []string{identity.RoleSubAuthority}, Grants: a.grants, IssuedAt: past}
		if err := c.Sign(root); err != nil {
			t.Fatal(err)
		}
		dar.AuthorityCredentials = append(dar.AuthorityCredentials, *c)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	src.PutDAR(dar)

	register := func(t *testing.T, local string, issuer *identity.IdentityKeyPair, hints []string) (*identity.IdentityRecord, *identity.IdentityKeyPair) {
		t.Helper()
		kp := mustKP(t)
		rec, _ := identity.NewIdentityRecord(local+"@"+domain, kp)
		if err := rec.Sign(kp); err != nil { // user self-sig (RelayHints NOT covered)
			t.Fatal(err)
		}
		if err := rec.IssueRoutingCredential(issuer, hints, time.Now()); err != nil { // operator routing
			t.Fatal(err)
		}
		src.PutIdentity(rec)
		return rec, kp
	}

	t.Run("routing credential verifies and carries hints", func(t *testing.T) {
		hints := []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA", "/ip4/10.0.0.2/tcp/7400/p2p/QmB"}
		register(t, "alice", routeIssuer, hints)
		time.Sleep(300 * time.Millisecond)
		got, err := reg.Lookup(ctx, "alice@"+domain)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if _, err := reg.VerifyManagedIdentity(ctx, got); err != nil {
			t.Fatalf("routing-credentialed identity verify failed: %v", err)
		}
		if !relayHintsEqual(got.RelayHints, hints) {
			t.Fatalf("hints = %v, want %v (mirrored from routing credential)", got.RelayHints, hints)
		}
	})

	t.Run("operator re-points hints WITHOUT the owner key", func(t *testing.T) {
		register(t, "carol", routeIssuer, []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA"})
		time.Sleep(300 * time.Millisecond)
		got, err := reg.Lookup(ctx, "carol@"+domain)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		// Operator (holds routeIssuer, NOT the owner key) re-issues routing with new hints.
		newHints := []string{"/ip4/10.0.0.9/tcp/7400/p2p/QmZ"}
		if err := got.IssueRoutingCredential(routeIssuer, newHints, time.Now()); err != nil {
			t.Fatal(err)
		}
		// No got.Sign(owner) — the owner self-signature is untouched.
		src.PutIdentity(got)
		time.Sleep(300 * time.Millisecond)
		again, err := reg.Lookup(ctx, "carol@"+domain)
		if err != nil {
			t.Fatalf("lookup after re-point: %v", err)
		}
		if _, err := reg.VerifyManagedIdentity(ctx, again); err != nil {
			t.Fatalf("verify after re-point: %v", err)
		}
		if !relayHintsEqual(again.RelayHints, newHints) {
			t.Fatalf("hints after re-point = %v, want %v", again.RelayHints, newHints)
		}
	})

	t.Run("issuer without routing grant rejected", func(t *testing.T) {
		rec, _ := register(t, "bob", noGrant, []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA"})
		if _, err := reg.VerifyManagedIdentity(ctx, rec); err == nil {
			t.Fatal("routing credential from a sub-authority lacking the routing grant must be rejected")
		}
	})

	t.Run("hints disagreeing with credential rejected", func(t *testing.T) {
		rec, _ := register(t, "dave", routeIssuer, []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA"})
		rec.RelayHints = []string{"/ip4/10.0.0.66/tcp/7400/p2p/QmEvil"} // tamper the mirror
		if _, err := reg.VerifyManagedIdentity(ctx, rec); err == nil {
			t.Fatal("RelayHints that disagree with the routing credential must be rejected")
		}
	})

	t.Run("subject mismatch rejected", func(t *testing.T) {
		rec, _ := register(t, "erin", routeIssuer, []string{"/ip4/10.0.0.1/tcp/7400/p2p/QmA"})
		rec.RoutingCredential.Subject = mustKP(t).Ed25519Public // cred for a different key
		if _, err := reg.VerifyManagedIdentity(ctx, rec); err == nil {
			t.Fatal("a routing credential whose Subject != the record key must be rejected")
		}
	})
}
