package node_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// Test harness for the DHT-free fleet: helpers to build serving (mailbox) nodes that hold a
// RecordStore, publish a domain's DAR + records across the fleet, and point every node's static
// _dmcn at the fleet so Lookup/Resolve works. Records are written to EVERY node's store (full
// replication) so a resolver reaches the record on whichever seed it dials.

// mustKPT generates an identity keypair or fails the test.
func mustKPT(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp
}

// seedOf returns a node's dialable seed multiaddr (first addr + /p2p/id).
func seedOf(n *node.Node) string {
	return fmt.Sprintf("%s/p2p/%s", n.Addrs()[0], n.PeerID())
}

// fleetNode creates a mailbox serving node (with a RecordStore) that can hold + serve fleet records.
func fleetNode(t *testing.T, ctx context.Context) *node.Node {
	t.Helper()
	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0",
		DataDir: t.TempDir(), Mailbox: true,
	})
	if err != nil {
		t.Fatalf("fleet node: %v", err)
	}
	return n
}

// signDAR creates + signs a default-policy DAR for a domain under a root key.
func signDAR(t *testing.T, domain string, root *identity.IdentityKeyPair) *identity.DomainAuthorityRecord {
	t.Helper()
	dar, err := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	return dar
}

// wireFleet publishes domain's DAR to each serving node and points every node's static _dmcn at the
// fleet (DAR fingerprint + all node seeds), so any node resolves any published record for the
// domain. Returns the signed DAR.
func wireFleet(t *testing.T, ctx context.Context, domain string, root *identity.IdentityKeyPair, nodes ...*node.Node) *identity.DomainAuthorityRecord {
	t.Helper()
	dar := signDAR(t, domain, root)
	sd := staticDNSFor(t, domain, root, nodes...)
	for _, n := range nodes {
		n.SetStaticDNS(sd)
		if n.Records() != nil {
			if err := n.Records().PutDAR(ctx, dar); err != nil {
				t.Fatalf("put DAR: %v", err)
			}
		}
	}
	return dar
}

// staticDNSFor builds the static _dmcn map for a domain (DAR fingerprint + the given nodes' seeds)
// so an additional (client) node can be pointed at the same fleet.
func staticDNSFor(t *testing.T, domain string, root *identity.IdentityKeyPair, nodes ...*node.Node) map[string]domainverify.Record {
	t.Helper()
	dar, err := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	seeds := make([]string, 0, len(nodes))
	for _, n := range nodes {
		seeds = append(seeds, seedOf(n))
	}
	return map[string]domainverify.Record{domain: {Fingerprint: dar.Fingerprint(), Seeds: seeds}}
}

// fleetDNSFromDAR builds a static _dmcn map pointing at the given serving nodes (their seeds) with a
// specific DAR's fingerprint — for pointing a CLIENT node at a fleet whose DAR the test already built.
func fleetDNSFromDAR(domain string, dar *identity.DomainAuthorityRecord, servers ...*node.Node) map[string]domainverify.Record {
	seeds := make([]string, 0, len(servers))
	for _, s := range servers {
		seeds = append(seeds, seedOf(s))
	}
	return map[string]domainverify.Record{domain: {Fingerprint: dar.Fingerprint(), Seeds: seeds}}
}

// putRec replicates a signed IdentityRecord to every serving node's RecordStore (the DHT-free
// stand-in for a registration that fanned out to the whole fleet). Registry().Lookup reads the
// RecordStore local-first, so a serving node that holds the record resolves it without static DNS.
func putRec(t *testing.T, ctx context.Context, rec *identity.IdentityRecord, nodes ...*node.Node) {
	t.Helper()
	for _, n := range nodes {
		if n.Records() != nil {
			if err := n.Records().PutIdentity(ctx, rec); err != nil {
				t.Fatalf("put record %s: %v", rec.Address, err)
			}
		}
	}
}

// putDAR replicates a signed DAR to every serving node's RecordStore.
func putDAR(t *testing.T, ctx context.Context, dar *identity.DomainAuthorityRecord, nodes ...*node.Node) {
	t.Helper()
	for _, n := range nodes {
		if n.Records() != nil {
			if err := n.Records().PutDAR(ctx, dar); err != nil {
				t.Fatalf("put DAR %s: %v", dar.Domain, err)
			}
		}
	}
}
