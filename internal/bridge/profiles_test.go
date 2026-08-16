package bridge_test

import (
	"context"
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestInboundMultiProfileMapping: a single bridge serving two {bridge↔dmcn} pairs maps an
// inbound recipient to the DMCN domain of its bridge-domain profile.
func TestInboundMultiProfileMapping(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	recipientKP := mustKeyPair(t)
	var gotAddr string
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		gotAddr = addr
		return recordFor(addr, recipientKP), nil
	}
	store := &capturingStore{}
	h := bridge.NewInboundHandler(bridge.InboundConfig{
		BridgeKP:     bridgeKP,
		BridgeAddr:   tBridgeAddr,
		AuthVerifier: passingAuth(),
		Lookup:       lookup,
		Deliver:      store.fn,
		BridgeDomain: tBridgeDomain,
		DMCNDomain:   tDMCNDomain,
		Profiles:     []bridge.DomainProfile{{BridgeDomain: "bridge.bob.com", DMCNDomain: "bob.com"}},
		Log:          testLog(),
	})

	// Recipient on the bob profile → mapped to bob.com.
	if err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "y@bridge.bob.com", []byte("From: ext@gmail.com\r\n\r\nhi")); err != nil {
		t.Fatalf("inbound bob: %v", err)
	}
	if gotAddr != "y@bob.com" {
		t.Fatalf("bob profile mapped to %q, want y@bob.com", gotAddr)
	}
	// Recipient on the default profile → mapped to the default DMCN domain.
	if err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "x@bridge.localhost", []byte("From: ext@gmail.com\r\n\r\nhi")); err != nil {
		t.Fatalf("inbound default: %v", err)
	}
	if gotAddr != "x@dmcn.localhost" {
		t.Fatalf("default profile mapped to %q, want x@dmcn.localhost", gotAddr)
	}
}

// TestOutboundMultiProfileFromRewrite: outbound From is rewritten to the bridge domain of the
// sender's DMCN-domain profile, and a sender on no served domain is refused.
func TestOutboundMultiProfileFromRewrite(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	deliverer := &bridge.StubSMTPDeliverer{}
	h := bridge.NewOutboundHandler(bridge.OutboundConfig{
		BridgeKP:   bridgeKP,
		BridgeAddr: tBridgeAddr,
		Deliverer:  deliverer,
		Lookup: func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
			return recordFor(addr, senderKP), nil
		},
		BridgeDomain: tBridgeDomain,
		DMCNDomain:   tDMCNDomain,
		Profiles:     []bridge.DomainProfile{{BridgeDomain: "bridge.bob.com", DMCNDomain: "bob.com"}},
		Log:          testLog(),
	})

	// Sender on bob.com → From rewritten to @bridge.bob.com.
	if _, err := h.HandleEnvelope(context.Background(), sealedToBridge(t, senderKP, bridgeKP, "carol@bob.com", "ext@gmail.com", "hi")); err != nil {
		t.Fatalf("bob outbound: %v", err)
	}
	// Sender on the default DMCN domain → From rewritten to the default bridge domain.
	if _, err := h.HandleEnvelope(context.Background(), sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext2@gmail.com", "hi")); err != nil {
		t.Fatalf("default outbound: %v", err)
	}
	// Sender on a domain the bridge does not serve → refused (open-relay guard).
	if _, err := h.HandleEnvelope(context.Background(), sealedToBridge(t, senderKP, bridgeKP, "eve@evil.com", "ext3@gmail.com", "hi")); !errors.Is(err, bridge.ErrSenderNotAuthorized) {
		t.Fatalf("non-served sender: want ErrSenderNotAuthorized, got %v", err)
	}

	froms := map[string]string{}
	for _, m := range deliverer.Messages {
		froms[m.To] = m.From
	}
	if froms["ext@gmail.com"] != "carol@bridge.bob.com" {
		t.Fatalf("bob From = %q, want carol@bridge.bob.com", froms["ext@gmail.com"])
	}
	if froms["ext2@gmail.com"] != "alice@bridge.localhost" {
		t.Fatalf("default From = %q, want alice@bridge.localhost", froms["ext2@gmail.com"])
	}
	if _, sent := froms["ext3@gmail.com"]; sent {
		t.Fatal("a non-served sender's mail must not be delivered")
	}
}
