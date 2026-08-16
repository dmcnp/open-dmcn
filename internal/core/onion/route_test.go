package onion

import (
	"testing"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

func desc(peerID, ip string) identity.RelayDescriptor {
	return identity.RelayDescriptor{
		PeerID:     peerID, // X25519Public irrelevant to selection
		Multiaddrs: []string{"/ip4/" + ip + "/tcp/4001"},
	}
}

func descDomain(peerID, ip, domain string) identity.RelayDescriptor {
	d := desc(peerID, ip)
	d.Domain = domain
	return d
}

// TestSelectRouteDomainDiversity verifies operator (domain) diversity: a strict
// route must use 3 distinct domains, and a candidate set with only 2 domains
// cannot fill a 3-hop strict route even when subnets differ.
func TestSelectRouteDomainDiversity(t *testing.T) {
	threeDomains := []identity.RelayDescriptor{
		descDomain("a", "10.0.1.1", "a.test"),
		descDomain("b", "10.0.2.1", "b.test"),
		descDomain("exit", "10.0.3.1", "c.test"),
	}
	route, err := SelectRoute(threeDomains, "exit", RouteOptions{})
	if err != nil {
		t.Fatalf("strict select with 3 domains: %v", err)
	}
	seen := map[string]bool{}
	for _, h := range route {
		for _, c := range threeDomains {
			if c.PeerID == h.PeerID && c.Domain != "" {
				if seen[c.Domain] {
					t.Fatalf("two hops share domain %q", c.Domain)
				}
				seen[c.Domain] = true
			}
		}
	}

	// Distinct subnets but only 2 domains ⇒ strict route impossible (exit reserves
	// one domain, leaving a single domain for two earlier hops).
	twoDomains := []identity.RelayDescriptor{
		descDomain("a", "10.0.1.1", "a.test"),
		descDomain("b", "10.0.2.1", "a.test"),
		descDomain("exit", "10.0.3.1", "b.test"),
	}
	if _, err := SelectRoute(twoDomains, "exit", RouteOptions{}); err == nil {
		t.Fatal("strict route across only 2 domains must fail operator diversity")
	}
	// Relaxed mode ignores operator diversity, so the same set succeeds.
	if _, err := SelectRoute(twoDomains, "exit", RouteOptions{Relaxed: true}); err != nil {
		t.Fatalf("relaxed select should ignore domain diversity: %v", err)
	}
}

func candidatesDistinctSubnets() []identity.RelayDescriptor {
	return []identity.RelayDescriptor{
		desc("relayA", "10.0.1.1"),
		desc("relayB", "10.0.2.1"),
		desc("relayExit", "10.0.3.1"),
	}
}

func TestSelectRouteStrict(t *testing.T) {
	route, err := SelectRoute(candidatesDistinctSubnets(), "relayExit", RouteOptions{})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(route) != 3 {
		t.Fatalf("route length = %d, want 3", len(route))
	}
	if route[len(route)-1].PeerID != "relayExit" {
		t.Fatalf("exit must be the last hop, got %q", route[len(route)-1].PeerID)
	}
	seen := map[string]bool{}
	for _, h := range route {
		if seen[h.PeerID] {
			t.Fatalf("duplicate hop %q", h.PeerID)
		}
		seen[h.PeerID] = true
	}
}

// Strict mode rejects a 3-node cluster that shares a subnet; relaxed mode accepts
// it — the minimum viable topology for the proof-of-concept.
func TestSelectRouteRelaxedSameSubnet(t *testing.T) {
	sameSubnet := []identity.RelayDescriptor{
		desc("relayA", "127.0.0.1"),
		desc("relayB", "127.0.0.1"),
		desc("relayExit", "127.0.0.1"),
	}

	if _, err := SelectRoute(sameSubnet, "relayExit", RouteOptions{}); err == nil {
		t.Fatal("strict mode must reject a same-subnet cluster")
	}

	route, err := SelectRoute(sameSubnet, "relayExit", RouteOptions{Relaxed: true})
	if err != nil {
		t.Fatalf("relaxed select: %v", err)
	}
	if len(route) != 3 || route[2].PeerID != "relayExit" {
		t.Fatalf("unexpected route %+v", route)
	}
}

func TestSelectRouteInsufficient(t *testing.T) {
	two := []identity.RelayDescriptor{desc("relayA", "10.0.1.1"), desc("relayExit", "10.0.2.1")}
	if _, err := SelectRoute(two, "relayExit", RouteOptions{}); err == nil {
		t.Fatal("expected error with only 2 candidates for a 3-hop route")
	}
}

func TestSelectRouteExitMissing(t *testing.T) {
	if _, err := SelectRoute(candidatesDistinctSubnets(), "nope", RouteOptions{}); err == nil {
		t.Fatal("expected error when exit is not among candidates")
	}
}

// A requested guard is pinned as the entry hop (route[0]) on every draw.
func TestSelectRouteGuardPinned(t *testing.T) {
	for i := 0; i < 8; i++ {
		route, err := SelectRoute(candidatesDistinctSubnets(), "relayExit", RouteOptions{Guard: "relayB"})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if route[0].PeerID != "relayB" {
			t.Fatalf("guard must be the entry hop, got %q", route[0].PeerID)
		}
		if route[len(route)-1].PeerID != "relayExit" {
			t.Fatalf("exit must be last, got %q", route[len(route)-1].PeerID)
		}
	}
}

// An unknown guard (or one equal to the exit) is ignored, not an error.
func TestSelectRouteGuardIgnoredWhenAbsent(t *testing.T) {
	if _, err := SelectRoute(candidatesDistinctSubnets(), "relayExit", RouteOptions{Guard: "ghost"}); err != nil {
		t.Fatalf("unknown guard should be ignored: %v", err)
	}
	if _, err := SelectRoute(candidatesDistinctSubnets(), "relayExit", RouteOptions{Guard: "relayExit"}); err != nil {
		t.Fatalf("guard==exit should be ignored: %v", err)
	}
}

func TestSelectRouteCustomHops(t *testing.T) {
	c := []identity.RelayDescriptor{
		desc("a", "10.0.1.1"), desc("b", "10.0.2.1"),
	}
	route, err := SelectRoute(c, "b", RouteOptions{Hops: 2})
	if err != nil {
		t.Fatalf("2-hop select: %v", err)
	}
	if len(route) != 2 || route[1].PeerID != "b" {
		t.Fatalf("unexpected 2-hop route %+v", route)
	}
}
