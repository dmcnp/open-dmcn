package bridge_test

import (
	"context"
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// sealedWithSubject builds an envelope to the bridge with a caller-chosen subject
// and body (sealedToBridge hardcodes the subject).
func sealedWithSubject(t *testing.T, senderKP, bridgeKP *identity.IdentityKeyPair, sender, recipient, subject, body string) *message.EncryptedEnvelope {
	t.Helper()
	msg, err := message.NewPlaintextMessage(sender, recipient, subject, body, senderKP.Ed25519Public)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(senderKP.Ed25519Private); err != nil {
		t.Fatalf("sign: %v", err)
	}
	env, err := message.Encrypt(sm, []message.RecipientInfo{{DeviceID: senderKP.DeviceID, X25519Pub: bridgeKP.X25519Public}})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return env
}

// A subject carrying CR/LF (a header-injection attempt) is refused before any
// SMTP delivery happens.
func TestOutboundRejectsHeaderInjectionSubject(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedWithSubject(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "Hi\r\nBcc: victim@evil.com", "body")

	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP)

	_, err := h.HandleEnvelope(context.Background(), env)
	if !errors.Is(err, bridge.ErrUnsafeHeader) {
		t.Fatalf("expected ErrUnsafeHeader, got %v", err)
	}
	if len(deliverer.Messages) != 0 {
		t.Fatal("must not deliver a message with an injected header")
	}
}

// A CR/LF in the recipient address is likewise refused.
func TestOutboundRejectsHeaderInjectionRecipient(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedWithSubject(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com\r\nBcc: x@evil.com", "Hello", "body")

	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP)

	_, err := h.HandleEnvelope(context.Background(), env)
	if !errors.Is(err, bridge.ErrUnsafeHeader) {
		t.Fatalf("expected ErrUnsafeHeader, got %v", err)
	}
	if len(deliverer.Messages) != 0 {
		t.Fatal("must not deliver to an injected recipient")
	}
}

// A body containing newlines is fine — only header fields are checked.
func TestOutboundAllowsNewlinesInBody(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedWithSubject(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "Hello", "line one\r\nline two\r\n")

	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP)

	if _, err := h.HandleEnvelope(context.Background(), env); err != nil {
		t.Fatalf("a multi-line body must be delivered, got %v", err)
	}
	if len(deliverer.Messages) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliverer.Messages))
	}
}
