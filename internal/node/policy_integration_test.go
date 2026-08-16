package node_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

func okDNS(context.Context, string, string) error { return nil }

// TestRelayFetchPolicyRejectsPending verifies the relay's FETCH gate (wired to
// registry.AddressUsable): on a require-countersign domain, an uncountersigned
// address cannot read its mailbox, but once countersigned + republished it can.
func TestRelayFetchPolicyRejectsPending(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	relayNode, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr:  "/ip4/127.0.0.1/tcp/0",
		DataDir:     t.TempDir(),
		Mailbox:     true,
		DNSVerifier: okDNS, // stub DAR DNS anchoring
	})
	if err != nil {
		t.Fatalf("relay node: %v", err)
	}
	defer relayNode.Close()

	hints := relayNode.RelayHints()
	relayHint := hints[0]
	info, err := node.ParseRelayHint(relayHint)
	if err != nil {
		t.Fatal(err)
	}

	client, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0", Peers: []string{relayHint}, DNSVerifier: okDNS})
	if err != nil {
		t.Fatalf("client node: %v", err)
	}
	defer client.Close()
	if err := client.ConnectPeer(relayHint); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(400 * time.Millisecond)

	const domain = "managed.me"
	root, _ := identity.GenerateIdentityKeyPair()
	dar, _ := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	dar.PolicyFlags |= identity.PolicyRequireCountersign
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	putDAR(t, ctx, dar, relayNode)

	// Uncountersigned alice, relay-hinted at the mailbox node.
	alice, _ := identity.GenerateIdentityKeyPair()
	rec, _ := identity.NewIdentityRecord("alice@managed.me", alice)
	rec.RelayHints = []string{relayHint}
	if err := rec.Sign(alice); err != nil {
		t.Fatal(err)
	}
	putRec(t, ctx, rec, relayNode)
	time.Sleep(300 * time.Millisecond)

	// FETCH must be denied while pending.
	_, _, err = client.Relay().ClientMailboxList(ctx, info.ID, alice, "alice@managed.me", 50, nil)
	if err == nil || !strings.Contains(err.Error(), "POLICY_PENDING") {
		t.Fatalf("pending FETCH = %v, want POLICY_PENDING", err)
	}

	// Issue an address credential + republish → mailbox becomes readable.
	rec.VerificationTier = identity.TierDomainDNS
	if err := rec.Sign(alice); err != nil {
		t.Fatal(err)
	}
	if err := rec.IssueAddressCredential(root, time.Now()); err != nil {
		t.Fatal(err)
	}
	putRec(t, ctx, rec, relayNode)
	time.Sleep(300 * time.Millisecond)

	if _, _, err := client.Relay().ClientMailboxList(ctx, info.ID, alice, "alice@managed.me", 50, nil); err != nil {
		t.Fatalf("countersigned FETCH = %v, want success", err)
	}
}
