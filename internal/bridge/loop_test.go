package bridge_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// msgWithReceived builds a raw message carrying n Received header fields.
func msgWithReceived(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("Received: from a.example by b.example; Mon, 01 Jan 2024 00:00:00 +0000\r\n")
	}
	b.WriteString("From: x@gmail.com\r\nSubject: hi\r\n\r\nbody\r\n")
	return []byte(b.String())
}

// A message that has traversed too many MTAs is dropped as a loop, before any
// recipient lookup or storage.
func TestInboundDropsMailLoop(t *testing.T) {
	store := &capturingStore{}
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) {
		t.Fatal("recipient lookup must not run for a looped message")
		return nil, nil
	}
	h := newInbound(passingAuth(), lookup, store.fn, mustKeyPair(t))

	err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "alice@bridge.localhost", msgWithReceived(26))
	if !errors.Is(err, bridge.ErrMailLoop) {
		t.Fatalf("expected ErrMailLoop, got %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("a looped message must not be stored, got %d", store.calls)
	}
}

// A message just under the hop limit is delivered normally.
func TestInboundAllowsUnderHopLimit(t *testing.T) {
	store := &capturingStore{}
	recipientKP := mustKeyPair(t)
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, recipientKP), nil
	}
	h := newInbound(passingAuth(), lookup, store.fn, mustKeyPair(t))

	if err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "alice@bridge.localhost", msgWithReceived(3)); err != nil {
		t.Fatalf("a normal message must be delivered, got %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("expected one stored message, got %d", store.calls)
	}
}

// An undeliverable message from the null sender must be dropped silently, not
// rejected — rejecting it would trigger a bounce loop.
func TestInboundSuppressesBounceForNullSender(t *testing.T) {
	store := &capturingStore{}
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) {
		return nil, errors.New("no record for that address")
	}
	h := newInbound(passingAuth(), lookup, store.fn, mustKeyPair(t))

	err := h.HandleMessage(context.Background(), "1.2.3.4", "<>", "ghost@bridge.localhost",
		[]byte("From: postmaster@gmail.com\r\nSubject: Delivery failure\r\n\r\nbounce body"))
	if err != nil {
		t.Fatalf("null-sender undeliverable must be dropped silently, got %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("nothing should be stored, got %d", store.calls)
	}
}

// An undeliverable auto-submitted message (e.g. a vacation reply) is likewise
// dropped silently rather than bounced.
func TestInboundSuppressesBounceForAutoSubmitted(t *testing.T) {
	store := &capturingStore{}
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) {
		return nil, errors.New("no record for that address")
	}
	h := newInbound(passingAuth(), lookup, store.fn, mustKeyPair(t))

	raw := []byte("From: vacation@gmail.com\r\nAuto-Submitted: auto-replied\r\nSubject: Out of office\r\n\r\naway")
	err := h.HandleMessage(context.Background(), "1.2.3.4", "vacation@gmail.com", "ghost@bridge.localhost", raw)
	if err != nil {
		t.Fatalf("auto-submitted undeliverable must be dropped, got %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("nothing should be stored, got %d", store.calls)
	}
}

// A normal undeliverable message (real sender, not auto) is still rejected so a
// legitimate bounce can be generated.
func TestInboundStillRejectsNormalUndeliverable(t *testing.T) {
	store := &capturingStore{}
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) {
		return nil, errors.New("no record for that address")
	}
	h := newInbound(passingAuth(), lookup, store.fn, mustKeyPair(t))

	err := h.HandleMessage(context.Background(), "1.2.3.4", "real@gmail.com", "ghost@bridge.localhost",
		[]byte("From: real@gmail.com\r\nSubject: hello\r\n\r\nhi"))
	if !errors.Is(err, bridge.ErrRecipientNotFound) {
		t.Fatalf("expected ErrRecipientNotFound for a normal undeliverable, got %v", err)
	}
}

// The same DMCN message delivered twice reaches the legacy recipient only once.
func TestOutboundDeduplicatesByMessageID(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP)

	r1, err := h.HandleEnvelope(context.Background(), env)
	if err != nil || r1 == nil || !r1.Success {
		t.Fatalf("first delivery should succeed: err=%v receipt=%+v", err, r1)
	}
	r2, err := h.HandleEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("duplicate delivery must not error: %v", err)
	}
	if r2 == nil || !r2.Success {
		t.Fatalf("duplicate should still return a success receipt, got %+v", r2)
	}
	if len(deliverer.Messages) != 1 {
		t.Fatalf("duplicate must not be re-delivered, got %d deliveries", len(deliverer.Messages))
	}
}
