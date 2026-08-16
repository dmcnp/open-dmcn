package bridge_test

import (
	"context"
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// newOutboundAuthz builds an outbound handler with explicit relay-authorization
// config (allowed sender domains + outbound rate limit).
func newOutboundAuthz(t *testing.T, lookup bridge.LookupFunc, deliverer bridge.SMTPDeliverer, kp *identity.IdentityKeyPair, allowed []string, rateLimit int) *bridge.OutboundHandler {
	t.Helper()
	return bridge.NewOutboundHandler(bridge.OutboundConfig{
		BridgeKP:             kp,
		BridgeAddr:           tBridgeAddr,
		Deliverer:            deliverer,
		Lookup:               lookup,
		BridgeDomain:         tBridgeDomain,
		DMCNDomain:           tDMCNDomain,
		AllowedSenderDomains: allowed,
		OutboundRateLimit:    rateLimit,
		Log:                  testLog(),
	})
}

// A sender on a domain this bridge does not serve must be rejected before any
// SMTP delivery — the open-relay guard.
func TestOutboundRejectsUnauthorizedSenderDomain(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	// Sender is on some other DMCN domain, not this bridge's dmcn.localhost.
	env := sealedToBridge(t, senderKP, bridgeKP, "mallory@other.dmcn", "ext@gmail.com", "spam")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutboundAuthz(t, func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP, nil, 0)

	receipt, err := h.HandleEnvelope(context.Background(), env)
	if !errors.Is(err, bridge.ErrSenderNotAuthorized) {
		t.Fatalf("expected ErrSenderNotAuthorized, got %v", err)
	}
	if receipt != nil {
		t.Fatal("no receipt should be issued for an unauthorized sender")
	}
	if len(deliverer.Messages) != 0 {
		t.Fatal("must not deliver for an unauthorized sender")
	}
}

// A sender on a domain in the explicit allow-list (beyond the default
// DMCNDomain) is authorized.
func TestOutboundAllowsExtraSenderDomain(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@partner.example", "ext@gmail.com", "hi")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutboundAuthz(t, func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP, []string{"dmcn.localhost", "partner.example"}, 0)

	receipt, err := h.HandleEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("authorized sender should deliver, got %v", err)
	}
	if receipt == nil || !receipt.Success {
		t.Fatalf("expected a success receipt, got %+v", receipt)
	}
	if len(deliverer.Messages) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliverer.Messages))
	}
}

// The per-sender outbound rate limit rejects deliveries past the configured cap,
// and the rejection happens without delivering or issuing a receipt.
func TestOutboundRateLimit(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutboundAuthz(t, func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP, nil, 2) // cap = 2 per hour

	send := func() error {
		// Fresh envelope each call (delivery consumes nothing reusable).
		env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
		_, err := h.HandleEnvelope(context.Background(), env)
		return err
	}

	if err := send(); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := send(); err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	if err := send(); !errors.Is(err, bridge.ErrOutboundRateLimited) {
		t.Fatalf("third delivery should be rate-limited, got %v", err)
	}
	if len(deliverer.Messages) != 2 {
		t.Fatalf("expected exactly 2 deliveries under the cap, got %d", len(deliverer.Messages))
	}
}
