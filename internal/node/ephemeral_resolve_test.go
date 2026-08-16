package node_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/pairing"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/registry"
)

// TestResolveEphemeralNoDNS verifies that a throwaway device-pairing record on the synthetic
// pairing.local domain — which has NO _dmcn TXT and NO DAR — resolves for a ClientOnly backend that
// knows the fleet only via Peers, with no static DNS wiring for pairing.local. This is the
// production device-pairing scenario (dmcn-web/b2c is a ClientOnly node that must resolve the
// ephemeral mailbox to LIST it and to STORE the clone response). The DNS/DAR-anchored resolver
// cannot reach pairing.local; the carve-out pulls the self-certifying record straight from a
// connected fleet peer, replacing the DHT's keyed global lookup the pairing flow used to rely on.
func TestResolveEphemeralNoDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relayNode := fleetNode(t, ctx)
	defer relayNode.Close()
	relaySeed := seedOf(relayNode)

	// A ClientOnly backend that knows the fleet ONLY via Peers — no RecordStore, and crucially no
	// static DNS for pairing.local (so if the carve-out were absent, Resolve would fail with
	// "pairing.local not registered").
	client, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0",
		ClientOnly: true, Peers: []string{relaySeed},
	})
	if err != nil {
		t.Fatalf("client node: %v", err)
	}
	defer client.Close()
	if err := client.ConnectPeer(relaySeed); err != nil {
		t.Fatalf("client connect relay: %v", err)
	}

	// Mint + publish the ephemeral record to the fleet's RecordStore (as pair-register's fan-out does).
	eph := mustKPT(t)
	ephAddr, err := pairing.EphemeralAddress()
	if err != nil {
		t.Fatalf("ephemeral addr: %v", err)
	}
	ephRec, err := pairing.NewEphemeralRecord(ephAddr, eph, relaySeed, time.Now())
	if err != nil {
		t.Fatalf("ephemeral record: %v", err)
	}
	putRec(t, ctx, ephRec, relayNode)

	// Resolve with no pairing.local DNS — the carve-out pulls it from the connected peer.
	got, err := client.Registry().Lookup(ctx, ephAddr)
	if err != nil {
		t.Fatalf("resolve ephemeral: %v", err)
	}
	if got.Address != ephAddr || !bytes.Equal(got.Ed25519Public, eph.Ed25519Public) {
		t.Fatalf("resolved record mismatch: got address %q", got.Address)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("resolved ephemeral record must self-verify: %v", err)
	}
	if len(got.RelayHints) == 0 || got.RelayHints[0] != relaySeed {
		t.Fatalf("resolved record lost its relay hint: %v", got.RelayHints)
	}

	// A pairing.local address the fleet does not hold ⇒ ErrNotFound (not a DNS/registration error).
	missing, err := pairing.EphemeralAddress()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Registry().Lookup(ctx, missing); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("missing ephemeral lookup = %v, want ErrNotFound", err)
	}
}
