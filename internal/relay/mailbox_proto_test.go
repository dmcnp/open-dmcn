package relay

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/registry"
)

// TestMailboxProtocolEndToEnd exercises the durable mailbox over real libp2p
// streams: STORE (durable) -> LIST (preview) -> BODY (on open) -> decrypt -> DELETE.
func TestMailboxProtocolEndToEnd(t *testing.T) {
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

	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	rsrv := New(srv, lookup, WithMailbox(NewMailboxStore(d)))
	rsrv.Start()
	defer rsrv.Stop()

	rcli := New(cli, lookup)

	// Compose -> split -> encrypt for the recipient.
	msg, err := message.NewPlaintextMessage("alice@dmcn.me", "bob@dmcn.me", "Hi Bob", "the body", senderKP.Ed25519Public)
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

	// STORE (durable, persisted to the mailbox).
	hash, err := rcli.ClientStoreWithAddress(ctx, srv.ID(), "alice@dmcn.me", senderKP, env)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	// LIST — preview without the body.
	entries, _, err := rcli.ClientMailboxList(ctx, srv.ID(), recipKP, "bob@dmcn.me", 10, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("list returned %d entries, want 1", len(entries))
	}
	var listed [32]byte
	copy(listed[:], entries[0].Hash)
	if listed != hash {
		t.Fatal("listed hash does not match stored hash")
	}
	// The durable entry carries the body's content address — the pointer future
	// per-fleet dedup keys on. It must survive Store -> List unchanged.
	if len(entries[0].BodyContentAddress) == 0 {
		t.Fatal("mailbox entry content address is empty (not persisted)")
	}
	if !bytes.Equal(entries[0].BodyContentAddress, env.BodyContentAddress) {
		t.Fatalf("entry content address drifted: got %x want %x", entries[0].BodyContentAddress, env.BodyContentAddress)
	}

	// BODY — fetched on open.
	body, err := rcli.ClientMailboxBody(ctx, srv.ID(), recipKP, "bob@dmcn.me", hash)
	if err != nil {
		t.Fatalf("body: %v", err)
	}

	// Reassemble the two parts and decrypt end-to-end.
	rebuilt, err := message.EncryptedEnvelopeFromProto(&dmcnpb.EncryptedEnvelope{
		Recipients:         entries[0].Recipients,
		EncryptedHeader:    entries[0].EncryptedHeader,
		HeaderNonce:        entries[0].HeaderNonce,
		HeaderTag:          entries[0].HeaderTag,
		HeaderSizeClass:    entries[0].HeaderSizeClass,
		EncryptedBody:      body.EncryptedBody,
		BodyNonce:          body.BodyNonce,
		BodyTag:            body.BodyTag,
		BodySizeClass:      body.BodySizeClass,
		BodyContentAddress: entries[0].BodyContentAddress,
	})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	// Keyless integrity holds on the reconstructed envelope (no CEK needed).
	if err := rebuilt.VerifyBodyContentAddress(); err != nil {
		t.Fatalf("keyless verify of reconstructed envelope: %v", err)
	}
	decH, err := message.DecryptHeader(rebuilt, recipKP.X25519Private, recipKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt header: %v", err)
	}
	if decH.Header.Subject != "Hi Bob" || decH.Header.SenderAddress != "alice@dmcn.me" {
		t.Fatalf("header preview wrong: %+v", decH.Header)
	}
	decC, err := message.DecryptBody(rebuilt, &decH.Header, recipKP.X25519Private, recipKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	if string(decC.Body.Content) != "the body" {
		t.Fatalf("body = %q", decC.Body.Content)
	}

	// DELETE — the explicit user action; the message is gone afterward.
	if err := rcli.ClientMailboxDelete(ctx, srv.ID(), recipKP, "bob@dmcn.me", hash); err != nil {
		t.Fatalf("delete: %v", err)
	}
	entries2, _, err := rcli.ClientMailboxList(ctx, srv.ID(), recipKP, "bob@dmcn.me", 10, nil)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(entries2) != 0 {
		t.Fatalf("after delete: %d entries, want 0", len(entries2))
	}
}

// TestMailboxChunkedLargeMessage stores a >4 MB message via chunked STORE and
// fetches its body via chunked BODY, asserting it reassembles byte-identical —
// proving message size is decoupled from the per-frame cap.
func TestMailboxChunkedLargeMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipKP, _ := identity.GenerateIdentityKeyPair()
	senderRec, _ := identity.NewIdentityRecord("alice@dmcn.me", senderKP)
	recipRec, _ := identity.NewIdentityRecord("bob@dmcn.me", recipKP)
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

	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	rsrv := New(srv, lookup, WithMailbox(NewMailboxStore(d)))
	rsrv.Start()
	defer rsrv.Stop()
	rcli := New(cli, lookup)

	// A ~9 MB body: spans multiple 1 MB chunk frames and exceeds the 4 MB cap.
	big := make([]byte, 9*1024*1024)
	for i := range big {
		big[i] = byte(i * 31)
	}
	msg, _ := message.NewPlaintextMessage("alice@dmcn.me", "bob@dmcn.me", "big attachment", "", senderKP.Ed25519Public)
	msg.Body = message.MessageBody{ContentType: "application/octet-stream", Content: big}
	sh, content, err := message.Split(msg, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{X25519Pub: recipKP.X25519Public}}, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}

	// Chunked durable STORE.
	hash, err := rcli.ClientStoreDurable(ctx, srv.ID(), "alice@dmcn.me", senderKP, env)
	if err != nil {
		t.Fatalf("store durable: %v", err)
	}

	entries, _, err := rcli.ClientMailboxList(ctx, srv.ID(), recipKP, "bob@dmcn.me", 10, nil)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: %v (n=%d)", err, len(entries))
	}

	// Chunked BODY fetch.
	body, err := rcli.ClientMailboxBody(ctx, srv.ID(), recipKP, "bob@dmcn.me", hash)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	rebuilt, err := message.EncryptedEnvelopeFromProto(&dmcnpb.EncryptedEnvelope{
		Recipients:         entries[0].Recipients,
		EncryptedHeader:    entries[0].EncryptedHeader,
		HeaderNonce:        entries[0].HeaderNonce,
		HeaderTag:          entries[0].HeaderTag,
		HeaderSizeClass:    entries[0].HeaderSizeClass,
		EncryptedBody:      body.EncryptedBody,
		BodyNonce:          body.BodyNonce,
		BodyTag:            body.BodyTag,
		BodySizeClass:      body.BodySizeClass,
		BodyContentAddress: entries[0].BodyContentAddress,
	})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	// Keyless integrity holds on the reconstructed envelope (no CEK needed).
	if err := rebuilt.VerifyBodyContentAddress(); err != nil {
		t.Fatalf("keyless verify of reconstructed envelope: %v", err)
	}
	decH, err := message.DecryptHeader(rebuilt, recipKP.X25519Private, recipKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt header: %v", err)
	}
	decC, err := message.DecryptBody(rebuilt, &decH.Header, recipKP.X25519Private, recipKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	if len(decC.Body.Content) != len(big) {
		t.Fatalf("body length = %d, want %d", len(decC.Body.Content), len(big))
	}
	for i := range big {
		if decC.Body.Content[i] != big[i] {
			t.Fatalf("body differs at byte %d", i)
		}
	}
}

// TestMailboxOpRejectsBadAuth ensures a mailbox op fails without a valid identity
// signature over the challenge nonce.
func TestMailboxOpWrongIdentityRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	recipKP, _ := identity.GenerateIdentityKeyPair()
	attackerKP, _ := identity.GenerateIdentityKeyPair()
	recipRec, _ := identity.NewIdentityRecord("bob@dmcn.me", recipKP)
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == "bob@dmcn.me" {
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

	d := openMailboxDS(t, t.TempDir())
	defer d.Close()
	rsrv := New(srv, lookup, WithMailbox(NewMailboxStore(d)))
	rsrv.Start()
	defer rsrv.Stop()
	rcli := New(cli, lookup)

	// The attacker signs the challenge with the wrong key while claiming bob's
	// address; the server must reject the auth.
	_, _, err := rcli.ClientMailboxList(ctx, srv.ID(), attackerKP, "bob@dmcn.me", 10, nil)
	if err == nil {
		t.Fatal("expected auth failure for a mismatched identity, got nil")
	}
}
