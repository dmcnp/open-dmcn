package node_test

import (
	"context"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
)

// TestSendOnionDeliversToMailbox is the B3 proof-of-concept on real nodes: a
// client builds a 3-hop onion over a 3-relay cluster (relaxed/dev diversity) and
// the message lands in the recipient's mailbox on the exit relay.
func TestSendOnionDeliversToMailbox(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	mkRelay := func(mailbox bool) *node.Node {
		cfg := node.Config{
			AllowedPeers: []string{"*"},
			ListenAddr:   "/ip4/127.0.0.1/tcp/0",
			DNSVerifier:  okDNS,
		}
		if mailbox {
			cfg.Mailbox = true
			cfg.DataDir = t.TempDir()
		}
		n, err := node.New(ctx, cfg)
		if err != nil {
			t.Fatalf("create relay: %v", err)
		}
		return n
	}

	relayA := mkRelay(false)
	defer relayA.Close()
	relayB := mkRelay(false)
	defer relayB.Close()
	relayExit := mkRelay(true) // recipient's relay = the onion exit
	defer relayExit.Close()

	relays := []*node.Node{relayA, relayB, relayExit}
	// Full mesh so onion hops can forward entry→middle→exit.
	for _, a := range relays {
		for _, b := range relays {
			if a != b {
				_ = a.ConnectPeer(b.RelayHints()[0])
			}
		}
	}

	exitHint := relayExit.RelayHints()[0]
	exitInfo, err := node.ParseRelayHint(exitHint)
	if err != nil {
		t.Fatal(err)
	}

	client, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		Peers:        []string{relayA.RelayHints()[0]},
		ClientOnly:   true,
		DNSVerifier:  okDNS,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()
	for _, r := range relays {
		_ = client.ConnectPeer(r.RelayHints()[0])
	}

	// Wait until the client can discover all three relay descriptors (published
	// asynchronously on start).
	deadline := time.Now().Add(40 * time.Second)
	for {
		if len(client.RelayDirectory(ctx)) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay directory never reached 3 descriptors (got %d)", len(client.RelayDirectory(ctx)))
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Register sender (so the exit can verify the STORE) and recipient (hinted at
	// the exit relay).
	senderKP, _ := identity.GenerateIdentityKeyPair()
	senderRec, _ := identity.NewIdentityRecord("sender@dmcn.localhost", senderKP)
	if err := senderRec.Sign(senderKP); err != nil {
		t.Fatal(err)
	}
	putRec(t, ctx, senderRec, relays...)

	recipientKP, _ := identity.GenerateIdentityKeyPair()
	recipientRec, _ := identity.NewIdentityRecord("recipient@dmcn.localhost", recipientKP)
	recipientRec.RelayHints = []string{exitHint}
	if err := recipientRec.Sign(recipientKP); err != nil {
		t.Fatal(err)
	}
	putRec(t, ctx, recipientRec, relays...)
	time.Sleep(500 * time.Millisecond)

	// Compose the split envelope.
	msg, _ := message.NewPlaintextMessage("sender@dmcn.localhost", "recipient@dmcn.localhost", "Hi", "secret over onion", senderKP.Ed25519Public)
	sh, content, err := message.Split(msg, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{X25519Pub: recipientRec.X25519Public}}, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.SendOnion(ctx, "sender@dmcn.localhost", senderKP, recipientRec, env, true); err != nil {
		t.Fatalf("SendOnion: %v", err)
	}

	// The message must be readable from the recipient's mailbox on the exit relay.
	page, _, err := client.Relay().ClientMailboxList(ctx, exitInfo.ID, recipientKP, "recipient@dmcn.localhost", 50, nil)
	if err != nil {
		t.Fatalf("mailbox list: %v", err)
	}
	if len(page) == 0 {
		t.Fatal("recipient mailbox is empty — onion delivery did not reach the exit")
	}
}
