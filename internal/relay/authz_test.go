package relay

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/peerpolicy"
	"dmcn.dev/open-dmcn/internal/registry"
)

// TestStoreRejectsUnvouchedSender verifies the STORE sender-authority gate (P4): the sender
// must be usable under its domain policy — the message-borne credential for STORE. A sender the
// policy marks un-vouched (an uncountersigned address on a require-countersign domain, modeled
// here by the address-usability check) is refused; a vouched sender is stored.
func TestStoreRejectsUnvouchedSender(t *testing.T) {
	ctx := context.Background()
	vouchedPub, vouchedPriv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unvouchedPub, unvouchedPriv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		switch addr {
		case "vouched@strict.test":
			return &identity.IdentityRecord{Address: addr, Ed25519Public: vouchedPub}, nil
		case "unvouched@strict.test":
			return &identity.IdentityRecord{Address: addr, Ed25519Public: unvouchedPub}, nil
		}
		return nil, registry.ErrNotFound
	}
	// Address-usability policy (mirrors registry.AddressUsable): the un-vouched address is refused.
	policy := func(_ context.Context, rec *identity.IdentityRecord) error {
		if rec.Address == "unvouched@strict.test" {
			return fmt.Errorf("address not countersigned")
		}
		return nil
	}
	h := newTestHost(t)
	defer h.Close()
	r := New(h, lookup, WithMailbox(newMailbox(t)), WithAccountStore(newAccounts(t)), WithFetchPolicy(policy))

	rxPub, _, _ := mailboxTestRecipient(t)
	env, hash := makeSplitEnvelope(t, rxPub, "s", "b")

	// Un-vouched sender (valid signature, registered) → refused by the domain-authority gate.
	badSig, err := crypto.Sign(unvouchedPriv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	resp := r.acceptEnvelope(ctx, "unvouched@strict.test", badSig, env, hash, arrivalDirect)
	if resp.GetError() == nil || resp.GetError().Code != "SENDER_NOT_VOUCHED" {
		t.Fatalf("STORE from an un-vouched sender = %v, want SENDER_NOT_VOUCHED", resp)
	}

	// Vouched sender → accepted and stored.
	goodSig, err := crypto.Sign(vouchedPriv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	resp = r.acceptEnvelope(ctx, "vouched@strict.test", goodSig, env, hash, arrivalDirect)
	if resp.GetStore() == nil {
		t.Fatalf("STORE from a vouched sender = %v, want a Store response", resp)
	}
}

// TestStoreVouchExemptionForCountersignRequest verifies the countersign-request
// bootstrap: an un-vouched sender's STORE is admitted ONLY when the exemption
// check passes (its own domain's countersign inbox is the sole recipient and the
// domain opens the request channel) — anything else stays SENDER_NOT_VOUCHED.
func TestStoreVouchExemptionForCountersignRequest(t *testing.T) {
	ctx := context.Background()
	senderPub, senderPriv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	inboxKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		switch addr {
		case "pending@strict.test":
			return &identity.IdentityRecord{Address: addr, Ed25519Public: senderPub}, nil
		case "countersign@strict.test":
			return &identity.IdentityRecord{Address: addr, Ed25519Public: inboxKP.Ed25519Public, X25519Public: inboxKP.X25519Public}, nil
		}
		return nil, registry.ErrNotFound
	}
	policy := func(_ context.Context, rec *identity.IdentityRecord) error {
		return fmt.Errorf("address pending domain countersignature")
	}
	allowRequests := true
	// Mirrors the node wiring: sender-domain channel open + every recipient is the
	// inbox's current X25519 key.
	exempt := func(ctx context.Context, senderRec *identity.IdentityRecord, env *message.EncryptedEnvelope) bool {
		if !allowRequests {
			return false
		}
		inboxRec, lerr := lookup(ctx, "countersign@strict.test")
		if lerr != nil || len(env.Recipients) == 0 {
			return false
		}
		for _, rcp := range env.Recipients {
			if rcp.RecipientXPub != inboxRec.X25519Public {
				return false
			}
		}
		return true
	}
	h := newTestHost(t)
	defer h.Close()
	r := New(h, lookup, WithMailbox(newMailbox(t)), WithAccountStore(newAccounts(t)),
		WithFetchPolicy(policy), WithStoreVouchExemption(exempt))

	// Sealed to the countersign inbox → admitted despite the failing vouch policy.
	env, hash := makeSplitEnvelope(t, inboxKP.X25519Public, "s", "please approve")
	sig, err := crypto.Sign(senderPriv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if resp := r.acceptEnvelope(ctx, "pending@strict.test", sig, env, hash, arrivalDirect); resp.GetStore() == nil {
		t.Fatalf("countersign request from a pending sender = %v, want a Store response", resp)
	}

	// Sealed to anyone else → still refused.
	otherPub, _, _ := mailboxTestRecipient(t)
	env2, hash2 := makeSplitEnvelope(t, otherPub, "s", "b")
	sig2, err := crypto.Sign(senderPriv, hash2[:])
	if err != nil {
		t.Fatal(err)
	}
	if resp := r.acceptEnvelope(ctx, "pending@strict.test", sig2, env2, hash2, arrivalDirect); resp.GetError() == nil || resp.GetError().Code != "SENDER_NOT_VOUCHED" {
		t.Fatalf("non-inbox recipient = %v, want SENDER_NOT_VOUCHED", resp)
	}

	// Request channel closed → refused even for the inbox.
	allowRequests = false
	env3, hash3 := makeSplitEnvelope(t, inboxKP.X25519Public, "s", "b")
	sig3, err := crypto.Sign(senderPriv, hash3[:])
	if err != nil {
		t.Fatal(err)
	}
	if resp := r.acceptEnvelope(ctx, "pending@strict.test", sig3, env3, hash3, arrivalDirect); resp.GetError() == nil || resp.GetError().Code != "SENDER_NOT_VOUCHED" {
		t.Fatalf("closed request channel = %v, want SENDER_NOT_VOUCHED", resp)
	}
}

// TestStoreNotConnectionGated verifies the per-op model (P4): STORE carries its credential in
// the message (sender signature), so it is NOT gated on the connection — a NON-federated peer
// can store a validly-signed message — while a connection-gated op (peer discovery) from that
// same peer is refused. This is what lets a credentialed cross-fleet sender or an end-user
// client deliver mail to a credential-gated relay.
func TestStoreNotConnectionGated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	senderKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	recipKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	senderRec, err := identity.NewIdentityRecord("alice@dmcn.me", senderKP)
	if err != nil {
		t.Fatal(err)
	}
	recipRec, err := identity.NewIdentityRecord("bob@dmcn.me", recipKP)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		switch addr {
		case "alice@dmcn.me":
			return senderRec, nil
		case "bob@dmcn.me":
			return recipRec, nil
		}
		return nil, registry.ErrNotFound
	}

	srv := newTestHost(t)
	defer srv.Close()
	cli := newTestHost(t)
	defer cli.Close()
	cli.Peerstore().AddAddrs(srv.ID(), srv.Addrs(), time.Hour)
	if err := cli.Connect(ctx, peer.AddrInfo{ID: srv.ID(), Addrs: srv.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// The server allowlists ONLY itself, so cli is NOT a federated peer.
	rsrv := New(srv, lookup, WithMailbox(newMailbox(t)),
		WithPeerPolicy(peerpolicy.NewPeerAllowList([]peer.ID{srv.ID()})))
	rsrv.Start()
	defer rsrv.Stop()
	rcli := New(cli, lookup)

	msg, err := message.NewPlaintextMessage("alice@dmcn.me", "bob@dmcn.me", "subj", "body", senderKP.Ed25519Public)
	if err != nil {
		t.Fatal(err)
	}
	sh, content, err := message.Split(msg, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{X25519Pub: recipKP.X25519Public}}, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}

	// STORE from the NON-federated cli succeeds — message-gated (sender signature), not connection-gated.
	if _, err := rcli.ClientStoreWithAddress(ctx, srv.ID(), "alice@dmcn.me", senderKP, env); err != nil {
		t.Fatalf("STORE from a non-federated peer should succeed (message-gated): %v", err)
	}
	// ...but a connection-gated op (peer discovery) from the same peer is refused.
	if _, err := rcli.ClientPeers(ctx, srv.ID()); err == nil {
		t.Error("peer discovery from a non-federated peer should be dropped")
	}
}
