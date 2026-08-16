package node

import (
	"testing"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestCredentialSetRolesAndGrants verifies the credentialSet keeps the whole credential per
// peer and answers role/grant queries from it — the basis for gating ops over the wire.
func TestCredentialSetRolesAndGrants(t *testing.T) {
	s := newCredentialSet()
	web := testPeerID(t, 1)
	other := testPeerID(t, 2)

	cred := &identity.Credential{
		Domain: "d.test",
		Roles:  []string{identity.RoleClient},
		Grants: []string{identity.GrantRouting, identity.GrantAddress},
	}
	s.add(web, cred)

	if !s.has(web) {
		t.Fatal("has(web) = false, want true after add")
	}
	if !s.hasRole(web, identity.RoleClient) {
		t.Fatal("hasRole(web, client) = false, want true")
	}
	if s.hasRole(web, identity.RoleNode) {
		t.Fatal("hasRole(web, node) = true, want false")
	}
	if !s.hasGrant(web, identity.GrantRouting, "d.test") || !s.hasGrant(web, identity.GrantAddress, "d.test") {
		t.Fatal("hasGrant(web, routing/address, d.test) = false, want true")
	}
	if s.hasGrant(web, identity.GrantDelegate, "d.test") {
		t.Fatal("hasGrant(web, grant, d.test) = true, want false (not granted)")
	}
	// Domain scoping: a grant for d.test does NOT cover a different domain.
	if s.hasGrant(web, identity.GrantRouting, "other.test") {
		t.Fatal("hasGrant(web, routing, other.test) = true, want false (out of domain)")
	}
	// ...but it does cover subdomains of the credential's domain.
	if !s.hasGrant(web, identity.GrantRouting, "sub.d.test") {
		t.Fatal("hasGrant(web, routing, sub.d.test) = false, want true (subdomain covered)")
	}
	if got := s.credential(web); got != cred {
		t.Fatalf("credential(web) = %v, want the stored credential", got)
	}

	// A peer that never joined has no roles/grants (fail closed).
	if s.has(other) || s.hasRole(other, identity.RoleClient) || s.hasGrant(other, identity.GrantRouting, "d.test") {
		t.Fatal("an unknown peer must report no membership/roles/grants")
	}
	if s.credential(other) != nil {
		t.Fatal("credential(unknown) must be nil")
	}

	// remove clears everything.
	s.remove(web)
	if s.has(web) || s.hasGrant(web, identity.GrantRouting, "d.test") || s.credential(web) != nil {
		t.Fatal("after remove, the peer must report no membership")
	}
}

// TestCredentialSetMultiDomain verifies a peer credentialed in several domains (hosted
// multi-tenant) is authorized per target domain — each presented credential accumulates.
func TestCredentialSetMultiDomain(t *testing.T) {
	s := newCredentialSet()
	webp := testPeerID(t, 1)

	s.add(webp, &identity.Credential{Domain: "alice.com", Roles: []string{identity.RoleClient}, Grants: []string{identity.GrantRouting}})
	s.add(webp, &identity.Credential{Domain: "bob.com", Roles: []string{identity.RoleClient}, Grants: []string{identity.GrantRouting, identity.GrantAddress}})

	// Routing is authorized for both domains (each from its own credential).
	if !s.hasGrant(webp, identity.GrantRouting, "alice.com") || !s.hasGrant(webp, identity.GrantRouting, "bob.com") {
		t.Fatal("routing must be authorized for both presented domains")
	}
	// The address grant is only on the bob.com credential.
	if s.hasGrant(webp, identity.GrantAddress, "alice.com") {
		t.Fatal("alice.com credential lacks the address grant; must not be authorized")
	}
	if !s.hasGrant(webp, identity.GrantAddress, "bob.com") {
		t.Fatal("bob.com credential has the address grant; must be authorized")
	}
	// A third, un-presented domain is not authorized.
	if s.hasGrant(webp, identity.GrantRouting, "eve.com") {
		t.Fatal("a domain the peer never presented must not be authorized")
	}
	// Re-adding alice.com overwrites only that domain's entry (bob.com retained).
	s.add(webp, &identity.Credential{Domain: "alice.com", Roles: []string{identity.RoleClient}})
	if s.hasGrant(webp, identity.GrantRouting, "alice.com") {
		t.Fatal("re-added alice.com (no grants) must replace the prior alice.com entry")
	}
	if !s.hasGrant(webp, identity.GrantRouting, "bob.com") {
		t.Fatal("bob.com entry must survive an alice.com re-add")
	}
}

// TestCredentialSetFleetVsDomainSeparation is the confused-deputy guard: a DOMAIN credential's
// grant must NEVER satisfy a FLEET grant check (and vice versa). Fleet ops (reserve/drain/
// handoff/accounts) consult only hasFleetGrant, so a customer domain's grant cannot authorize
// an action on the operator's fleet — the whole point of re-rooting fleet trust to the operator.
func TestCredentialSetFleetVsDomainSeparation(t *testing.T) {
	s := newCredentialSet()
	domainPeer := testPeerID(t, 1)
	fleetPeer := testPeerID(t, 2)

	// A DOMAIN credential carrying address + routing (e.g. a customer domain's issuer).
	s.add(domainPeer, &identity.Credential{Domain: "customer.com", Roles: []string{identity.RoleClient}, Grants: []string{identity.GrantAddress, identity.GrantRouting}})
	if !s.hasGrant(domainPeer, identity.GrantAddress, "customer.com") {
		t.Fatal("domain grant should satisfy the domain-scoped check for its own domain")
	}
	if s.hasFleetGrant(domainPeer, identity.GrantAddress) || s.hasFleetGrant(domainPeer, identity.GrantRouting) {
		t.Fatal("a DOMAIN credential's grant must NEVER authorize a fleet op (confused-deputy guard)")
	}
	if s.hasFleetRole(domainPeer, identity.RoleClient) {
		t.Fatal("a DOMAIN credential's role must not register as a fleet role")
	}

	// An operator-rooted FLEET credential carrying address + routing.
	s.addFleet(fleetPeer, &identity.Credential{Roles: []string{identity.RoleNode}, Grants: []string{identity.GrantAddress, identity.GrantRouting}})
	if !s.hasFleetGrant(fleetPeer, identity.GrantAddress) || !s.hasFleetGrant(fleetPeer, identity.GrantRouting) {
		t.Fatal("a fleet credential's grants must satisfy hasFleetGrant")
	}
	if !s.hasFleetRole(fleetPeer, identity.RoleNode) {
		t.Fatal("a fleet credential's role must satisfy hasFleetRole")
	}
	if s.hasGrant(fleetPeer, identity.GrantAddress, "customer.com") {
		t.Fatal("a FLEET credential (no domain authority) must not satisfy a domain-scoped grant check")
	}

	if !s.has(domainPeer) || !s.has(fleetPeer) {
		t.Fatal("has() must be true for a peer with either a domain or a fleet credential")
	}
	s.remove(fleetPeer)
	if s.has(fleetPeer) || s.hasFleetGrant(fleetPeer, identity.GrantAddress) {
		t.Fatal("after remove, the fleet peer must report nothing")
	}
}
