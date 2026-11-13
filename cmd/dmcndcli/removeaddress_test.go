package main

import (
	"context"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// tombstoneNode is a daemon serving mesh.example with its authority record in place, anchored at
// itself so the registry can verify the DAR without DNS. tombstoneKey runs against it directly: in
// production the CLI reaches the same calls through a client node dialled with --peers.
func tombstoneNode(t *testing.T) (*node.Node, *identity.IdentityKeyPair) {
	t.Helper()
	ctx := context.Background()
	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       "mesh.example",
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.Close() })

	root := testRoot(t)
	dar, err := buildDAR("mesh.example", root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.PublishDAR(ctx, dar); err != nil {
		t.Fatalf("publish DAR: %v", err)
	}
	n.MergeStaticDNS(map[string]domainverify.Record{
		"mesh.example": {Fingerprint: dar.Fingerprint(), Seeds: []string{n.Addrs()[0]}},
	})
	return n, root
}

// TestTombstoneKeyExtendsTheRemovalRecord pins what remove-address and `petition assign --replace`
// both depend on: a second tombstone for the same address EXTENDS the fleet's removal record rather
// than replacing it. A record that dropped an earlier binding would bring a dead key back to life,
// since the rebind gate reads the removal record to decide which keys are gone.
func TestTombstoneKeyExtendsTheRemovalRecord(t *testing.T) {
	n, root := tombstoneNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const address = "alice@mesh.example"
	first, second := testRoot(t).Ed25519Public, testRoot(t).Ed25519Public

	rev1, accepted, already, err := tombstoneKey(ctx, n, root, address, first)
	if err != nil {
		t.Fatalf("first tombstone: %v", err)
	}
	if already || accepted == 0 {
		t.Fatalf("first tombstone: already=%v accepted=%d, want a fresh publish", already, accepted)
	}

	// Again for the same key: nothing to publish, and it says so rather than bumping the revision.
	rev, _, already, err := tombstoneKey(ctx, n, root, address, first)
	if err != nil {
		t.Fatalf("repeat tombstone: %v", err)
	}
	if !already || rev != rev1 {
		t.Fatalf("repeat tombstone: already=%v rev=%d, want already at rev %d", already, rev, rev1)
	}

	rev2, _, already, err := tombstoneKey(ctx, n, root, address, second)
	if err != nil {
		t.Fatalf("second key: %v", err)
	}
	if already || rev2 <= rev1 {
		t.Fatalf("second key: already=%v rev=%d, want a new revision above %d", already, rev2, rev1)
	}

	dar, err := n.Registry().LookupDomainAuthority(ctx, "mesh.example")
	if err != nil {
		t.Fatal(err)
	}
	rm, err := n.FetchRemovalUnion(ctx, dar, address)
	if err != nil {
		t.Fatalf("read back the removal record: %v", err)
	}
	for _, k := range [][]byte{first, second} {
		if _, gone := rm.Removed(k); !gone {
			t.Errorf("key %x is missing from the removal record — it would be live again", k[:4])
		}
	}
	if len(rm.RemovedBindings) != 2 {
		t.Errorf("removal record holds %d binding(s), want exactly the two tombstoned keys", len(rm.RemovedBindings))
	}
}
