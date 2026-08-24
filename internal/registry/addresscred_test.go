package registry

import (
	"context"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestAddressCredentialManagedIdentity exercises the S3 address-credential path: a user
// record carrying a domain-issued address Credential (role "address", issued by a
// Grants:["address"] sub-authority that lives in the DAR) verifies as DomainDNS; a
// credential from a sub-authority WITHOUT the address grant, or one whose subject/domain
// doesn't match the record, is rejected.
func TestAddressCredentialManagedIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	reg, src := makeReg(t)

	const domain = "addr.test"
	past := time.Now().Add(-time.Hour)
	root := mustKP(t)
	addrIssuer := mustKP(t) // sub-authority that MAY issue addresses
	noGrant := mustKP(t)    // sub-authority that may NOT

	dar, _ := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	dar.AuthorityEffectiveFrom = past
	for _, a := range []struct {
		kp     *identity.IdentityKeyPair
		grants []string
	}{{addrIssuer, []string{identity.RoleAddress}}, {noGrant, nil}} {
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

	register := func(t *testing.T, local string, issuer *identity.IdentityKeyPair) *identity.IdentityRecord {
		t.Helper()
		kp := mustKP(t)
		rec, _ := identity.NewIdentityRecord(local+"@"+domain, kp)
		if err := rec.Sign(kp); err != nil { // user self-sig (dual binding)
			t.Fatal(err)
		}
		if err := rec.IssueAddressCredential(issuer, time.Now()); err != nil { // domain attestation
			t.Fatal(err)
		}
		src.PutIdentity(rec)
		return rec
	}

	t.Run("address credential verifies as DomainDNS", func(t *testing.T) {
		register(t, "alice", addrIssuer)
		time.Sleep(300 * time.Millisecond)
		got, err := reg.Lookup(ctx, "alice@"+domain)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if tier, err := reg.VerifyManagedIdentity(ctx, got); err != nil || tier != identity.TierDomainDNS {
			t.Fatalf("address-credentialed identity verify = (%s, %v), want DomainDNS", tier, err)
		}
	})

	t.Run("issuer without address grant rejected", func(t *testing.T) {
		register(t, "bob", noGrant)
		time.Sleep(300 * time.Millisecond)
		got, err := reg.Lookup(ctx, "bob@"+domain)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if tier, _ := reg.VerifyManagedIdentity(ctx, got); tier == identity.TierDomainDNS {
			t.Fatal("an address credential from a sub-authority lacking the address grant must NOT verify")
		}
	})

	t.Run("subject mismatch rejected", func(t *testing.T) {
		kp := mustKP(t)
		rec, _ := identity.NewIdentityRecord("eve@"+domain, kp)
		rec.Sign(kp)
		rec.IssueAddressCredential(addrIssuer, time.Now())
		rec.AddressCredential.Subject = mustKP(t).Ed25519Public // tamper: cred for a different key
		if tier, _ := reg.VerifyManagedIdentity(ctx, rec); tier == identity.TierDomainDNS {
			t.Fatal("an address credential whose Subject != the record key must be rejected")
		}
	})
}
