package node_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/relay"
)

// TestEndToEndAliceBob is the PRD-mandated end-to-end integration test.
// See PRD Section 5.4.
//
// Scenario:
//  1. Start two dmcn-node instances sharing a local DHT.
//  2. Generate identity alice@localhost on node-A. Register it.
//  3. Generate identity bob@localhost on node-B. Register it.
//  4. node-A looks up bob@localhost and retrieves his IdentityRecord. Signature validates.
//  5. node-A composes a PlaintextMessage, signs it, encrypts it to bob's X25519
//     public key, and STOREs it on node-B's relay.
//  6. node-B authenticates and FETCHes its pending envelopes. Decrypts the
//     envelope. Verifies the sender signature. Plaintext matches original.
//  7. node-B sends ACK. Delivery status is Delivered.
func TestEndToEndAliceBob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Start two serving (fleet) nodes.
	nodeA := fleetNode(t, ctx)
	defer nodeA.Close()
	nodeB := fleetNode(t, ctx)
	defer nodeB.Close()

	// Connect nodes to each other
	nodeBAddrs := nodeB.Addrs()
	if len(nodeBAddrs) == 0 {
		t.Fatal("node-B has no addresses")
	}
	if err := nodeA.ConnectPeer(nodeBAddrs[0]); err != nil {
		t.Fatalf("connect A→B: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Point the fleet resolver at both nodes for the localhost domain (DHT-free resolution).
	root := mustKPT(t)
	wireFleet(t, ctx, "localhost", root, nodeA, nodeB)

	// Step 2: Generate and register alice on node-A
	aliceKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate alice key pair: %v", err)
	}
	aliceRec, err := identity.NewIdentityRecord("alice@localhost", aliceKP)
	if err != nil {
		t.Fatalf("create alice record: %v", err)
	}
	if err := aliceRec.Sign(aliceKP); err != nil {
		t.Fatalf("sign alice record: %v", err)
	}
	putRec(t, ctx, aliceRec, nodeA, nodeB)

	// Step 3: Generate and register bob on node-B
	bobKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate bob key pair: %v", err)
	}
	bobRec, err := identity.NewIdentityRecord("bob@localhost", bobKP)
	if err != nil {
		t.Fatalf("create bob record: %v", err)
	}
	if err := bobRec.Sign(bobKP); err != nil {
		t.Fatalf("sign bob record: %v", err)
	}
	putRec(t, ctx, bobRec, nodeA, nodeB)

	// Step 4: node-A looks up bob's identity via the fleet resolver.
	lookedUpBob, err := nodeA.Lookup(ctx, "bob@localhost")
	if err != nil {
		t.Fatalf("lookup bob: %v", err)
	}
	if err := lookedUpBob.Verify(); err != nil {
		t.Fatalf("bob's identity signature invalid: %v", err)
	}
	if lookedUpBob.Address != "bob@localhost" {
		t.Errorf("bob address = %q, want %q", lookedUpBob.Address, "bob@localhost")
	}

	// Step 5: node-A composes, signs, encrypts, and STOREs message
	originalBody := "Hello Bob, this is Alice!"
	msg, err := message.NewPlaintextMessage(
		"alice@localhost",
		"bob@localhost",
		"Test Message",
		originalBody,
		aliceKP.Ed25519Public,
	)
	if err != nil {
		t.Fatalf("compose message: %v", err)
	}

	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(aliceKP.Ed25519Private); err != nil {
		t.Fatalf("sign message: %v", err)
	}

	recipients := []message.RecipientInfo{{
		DeviceID:  bobKP.DeviceID,
		X25519Pub: lookedUpBob.X25519Public,
	}}

	env, err := message.Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("encrypt message: %v", err)
	}

	// STORE on node-B's relay
	envHash, err := nodeA.Relay().ClientStoreWithAddress(
		ctx, nodeB.PeerID(), "alice@localhost", aliceKP, env,
	)
	if err != nil {
		t.Fatalf("store message: %v", err)
	}
	if envHash == [32]byte{} {
		t.Fatal("envelope hash is zero")
	}

	// Step 6: Bob's client connects to node-B to FETCH
	// (libp2p can't dial self, so Bob uses a separate client node)
	bobClient, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create bob client: %v", err)
	}
	defer bobClient.Close()

	// Connect bob's client to node-B
	if err := bobClient.ConnectPeer(nodeBAddrs[0]); err != nil {
		t.Fatalf("connect bob client → node-B: %v", err)
	}

	// bob's record is already published across the fleet (nodeA/nodeB); the FETCH auth resolves it
	// from there. Point bob's client at the fleet too so any lookup it makes resolves.
	bobClient.SetStaticDNS(staticDNSFor(t, "localhost", root, nodeA, nodeB))

	time.Sleep(200 * time.Millisecond)

	fetchedEnvs, fetchedHashes, err := bobClient.Relay().ClientFetch(
		ctx, nodeB.PeerID(), bobKP, "bob@localhost",
	)
	if err != nil {
		t.Fatalf("fetch messages: %v", err)
	}
	if len(fetchedEnvs) != 1 {
		t.Fatalf("fetched %d envelopes, want 1", len(fetchedEnvs))
	}

	// Decrypt
	decrypted, err := message.Decrypt(fetchedEnvs[0], bobKP.X25519Private, bobKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt message: %v", err)
	}

	// Verify sender signature
	if err := decrypted.Verify(); err != nil {
		t.Fatalf("verify sender signature: %v", err)
	}

	// Verify plaintext matches
	gotBody := string(decrypted.Plaintext.Body.Content)
	if gotBody != originalBody {
		t.Errorf("body = %q, want %q", gotBody, originalBody)
	}
	if decrypted.Plaintext.SenderAddress != "alice@localhost" {
		t.Errorf("sender = %q, want %q", decrypted.Plaintext.SenderAddress, "alice@localhost")
	}

	// Step 7: Bob's client sends ACK
	if err := bobClient.Relay().ClientAck(ctx, nodeB.PeerID(), fetchedHashes[0]); err != nil {
		t.Fatalf("ack message: %v", err)
	}

	// Verify delivery status on node-B's relay store
	status, err := nodeB.Relay().Store().DeliveryStatusOf(envHash)
	if err != nil {
		t.Fatalf("check delivery status: %v", err)
	}
	if status != relay.Delivered {
		t.Errorf("delivery status = %d, want Delivered (%d)", status, relay.Delivered)
	}
}

// TestStoreFromUnregisteredSender is the PRD-mandated rejection test.
// A STORE from an unregistered identity must be rejected by the relay.
func TestStoreFromUnregisteredSender(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create relay node
	relayNode, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create relay node: %v", err)
	}
	defer relayNode.Close()

	// Create client node that connects to relay
	client, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create client node: %v", err)
	}
	defer client.Close()

	relayAddrs := relayNode.Addrs()
	if err := client.ConnectPeer(relayAddrs[0]); err != nil {
		t.Fatalf("connect client → relay: %v", err)
	}

	// Generate an unregistered identity (NOT registered in DHT)
	unregKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Also need a registered recipient for the envelope
	recipKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate recipient key pair: %v", err)
	}

	// Compose a message from the unregistered sender
	msg, err := message.NewPlaintextMessage(
		"unregistered@localhost",
		"anyone@localhost",
		"Spam",
		"This should be rejected",
		unregKP.Ed25519Public,
	)
	if err != nil {
		t.Fatalf("compose message: %v", err)
	}

	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(unregKP.Ed25519Private); err != nil {
		t.Fatalf("sign message: %v", err)
	}

	recipients := []message.RecipientInfo{{
		DeviceID:  recipKP.DeviceID,
		X25519Pub: recipKP.X25519Public,
	}}

	env, err := message.Encrypt(sm, recipients)
	if err != nil {
		t.Fatalf("encrypt message: %v", err)
	}

	// Attempt STORE — should be rejected
	_, err = client.Relay().ClientStoreWithAddress(
		ctx, relayNode.PeerID(), "unregistered@localhost", unregKP, env,
	)
	if err == nil {
		t.Fatal("STORE from unregistered sender should fail")
	}
	if err.Error() == "" {
		t.Fatal("expected error message")
	}
	t.Logf("correctly rejected with: %v", err)
}

// TestRegistryRegisterLookup tests basic registry operations.
func TestRegistryRegisterLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Two serving nodes forming a fleet for the localhost domain.
	n1 := fleetNode(t, ctx)
	defer n1.Close()
	n2 := fleetNode(t, ctx)
	defer n2.Close()

	if err := n1.ConnectPeer(n2.Addrs()[0]); err != nil {
		t.Fatalf("connect nodes: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	wireFleet(t, ctx, "localhost", mustKPT(t), n1, n2)

	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	rec, err := identity.NewIdentityRecord("test@localhost", kp)
	if err != nil {
		t.Fatalf("create record: %v", err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatalf("sign record: %v", err)
	}

	// Publish across the fleet.
	putRec(t, ctx, rec, n1, n2)

	// Lookup from node2 via the fleet resolver.
	found, err := n2.Lookup(ctx, "test@localhost")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found.Address != "test@localhost" {
		t.Errorf("address = %q, want %q", found.Address, "test@localhost")
	}
	if err := found.Verify(); err != nil {
		t.Errorf("verify found record: %v", err)
	}
	if found.Fingerprint() != rec.Fingerprint() {
		t.Error("fingerprints differ after register/lookup")
	}
}

// TestRegistryNotFound tests that lookup of non-existent address returns error.
func TestRegistryNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	n, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	defer n.Close()

	_, err = n.Registry().Lookup(ctx, "nonexistent@localhost")
	if err == nil {
		t.Fatal("lookup of non-existent address should fail")
	}
}

// TestRelayPing tests the PING operation.
func TestRelayPing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	defer server.Close()

	client, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	if err := client.ConnectPeer(server.Addrs()[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}

	resp, err := client.Relay().ClientPing(ctx, server.PeerID())
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	if resp.Version == "" {
		t.Error("ping response version is empty")
	}
	if resp.UptimeSeconds < 0 {
		t.Errorf("uptime = %d, want >= 0", resp.UptimeSeconds)
	}
}

// TestRelayHints tests that RelayHints returns the node's own addresses only.
// Advertisement is decoupled from the infra peer list: a record advertises only
// the relay that hosts its mailbox, not every configured cluster peer.
func TestRelayHints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fakePeer := "/ip4/10.0.0.1/tcp/7400/p2p/QmFakeOrgPeer1"
	n, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
		Peers:      []string{fakePeer},
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	defer n.Close()

	hints := n.RelayHints()
	ownAddrs := n.Addrs()
	if len(ownAddrs) == 0 {
		t.Fatal("node has no addresses")
	}

	// Hints must be exactly the node's own addresses — no configured peers leak in.
	if len(hints) != len(ownAddrs) {
		t.Fatalf("hints = %v, want own addrs %v", hints, ownAddrs)
	}
	for _, h := range hints {
		if h == fakePeer {
			t.Errorf("configured peer must not appear in relay hints: %v", hints)
		}
	}
	if hints[0] != ownAddrs[0] {
		t.Errorf("first hint = %q, want own addr %q", hints[0], ownAddrs[0])
	}
}

// TestParseRelayHint tests parsing relay hint multiaddrs.
func TestParseRelayHint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create a node to get a valid multiaddr with peer ID.
	n, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	defer n.Close()

	addrs := n.Addrs()
	if len(addrs) == 0 {
		t.Fatal("no addresses")
	}

	info, err := node.ParseRelayHint(addrs[0])
	if err != nil {
		t.Fatalf("ParseRelayHint: %v", err)
	}
	if info.ID != n.PeerID() {
		t.Errorf("peer ID = %s, want %s", info.ID, n.PeerID())
	}

	// Invalid hint
	_, err = node.ParseRelayHint("not-a-multiaddr")
	if err == nil {
		t.Error("expected error for invalid multiaddr")
	}
}

// TestPeerDiscovery tests that peer discovery merges (and connects to) peers
// reported by a configured cluster peer via the /dmcn/peers/1.0.0 protocol.
func TestPeerDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// node2 is a plain cluster member.
	node2, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create node2: %v", err)
	}
	defer node2.Close()

	// node1 reports node2 in its peers list, so a peer that queries node1 via
	// /dmcn/peers/1.0.0 learns about node2.
	node1, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
		Peers:      node2.Addrs(),
	})
	if err != nil {
		t.Fatalf("create node1: %v", err)
	}
	defer node1.Close()

	if err := node1.ConnectPeer(node2.Addrs()[0]); err != nil {
		t.Fatalf("connect node1→node2: %v", err)
	}

	// A client that only knows node1 should discover node2 through peer discovery
	// (discoverPeers runs synchronously during node.New) and connect to it.
	clientNode, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
		Peers:      node1.Addrs(),
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer clientNode.Close()

	// The client should now be connected to the discovered node2.
	connected := false
	for _, p := range clientNode.Host().Network().Peers() {
		if p == node2.PeerID() {
			connected = true
			break
		}
	}
	if !connected {
		t.Errorf("expected client to connect to discovered peer node2 (%s), connected peers: %v",
			node2.PeerID(), clientNode.Host().Network().Peers())
	}
}

// TestRelayRateLimiting tests that the rate limiter rejects excessive STOREs.
func TestRelayRateLimiting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	server := fleetNode(t, ctx)
	defer server.Close()

	client, err := node.New(ctx, node.Config{AllowedPeers: []string{"*"},
		ListenAddr: "/ip4/127.0.0.1/tcp/0",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	if err := client.ConnectPeer(server.Addrs()[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// The sender's record must be resolvable for the STORE sender-verification gate.
	senderKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate sender key pair: %v", err)
	}
	senderRec, err := identity.NewIdentityRecord("ratelimit-sender@localhost", senderKP)
	if err != nil {
		t.Fatalf("create sender record: %v", err)
	}
	if err := senderRec.Sign(senderKP); err != nil {
		t.Fatalf("sign sender record: %v", err)
	}
	putRec(t, ctx, senderRec, server)

	recipKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate recipient key pair: %v", err)
	}

	// Send 100 messages (should all succeed)
	for i := 0; i < 100; i++ {
		msg, _ := message.NewPlaintextMessage(
			"ratelimit-sender@localhost", "recip@localhost",
			"", fmt.Sprintf("msg %d", i), senderKP.Ed25519Public,
		)
		sm := &message.SignedMessage{Plaintext: *msg}
		sm.Sign(senderKP.Ed25519Private)

		env, _ := message.Encrypt(sm, []message.RecipientInfo{{
			DeviceID: recipKP.DeviceID, X25519Pub: recipKP.X25519Public,
		}})

		_, err := client.Relay().ClientStoreWithAddress(
			ctx, server.PeerID(), "ratelimit-sender@localhost", senderKP, env,
		)
		if err != nil {
			t.Fatalf("store %d should succeed: %v", i, err)
		}
	}

	// 101st should be rate-limited
	msg, _ := message.NewPlaintextMessage(
		"ratelimit-sender@localhost", "recip@localhost",
		"", "one too many", senderKP.Ed25519Public,
	)
	sm := &message.SignedMessage{Plaintext: *msg}
	sm.Sign(senderKP.Ed25519Private)
	env, _ := message.Encrypt(sm, []message.RecipientInfo{{
		DeviceID: recipKP.DeviceID, X25519Pub: recipKP.X25519Public,
	}})

	_, err = client.Relay().ClientStoreWithAddress(
		ctx, server.PeerID(), "ratelimit-sender@localhost", senderKP, env,
	)
	if err == nil {
		t.Fatal("101st STORE should be rate-limited")
	}
	t.Logf("correctly rate-limited: %v", err)
}
