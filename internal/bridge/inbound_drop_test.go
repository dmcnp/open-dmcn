package bridge_test

import (
	"context"
	"errors"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// fixedAuth returns a preset AuthResult, letting tests drive the inbound
// handler's drop/classify decision without any DNS.
type fixedAuth struct{ res *bridge.AuthResult }

func (f fixedAuth) Verify(context.Context, string, string, []byte) (*bridge.AuthResult, error) {
	return f.res, nil
}

// A DMARC failure under a p=reject policy must be dropped before any recipient
// lookup or storage happens.
func TestInboundDropsHardFail(t *testing.T) {
	store := &capturingStore{}
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) {
		t.Fatal("recipient lookup must not run for a rejected message")
		return nil, nil
	}
	auth := fixedAuth{res: &bridge.AuthResult{DMARC: bridge.DMARCFail, DMARCPolicy: bridge.DMARCPolicyReject}}
	h := newInbound(auth, lookup, store.fn, mustKeyPair(t))

	err := h.HandleMessage(context.Background(), "9.9.9.9", "ext@gmail.com", "alice@bridge.localhost", []byte("From: x@gmail.com\r\n\r\nhi"))
	if !errors.Is(err, bridge.ErrMessageRejected) {
		t.Fatalf("expected ErrMessageRejected, got %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("rejected message must not be stored, got %d", store.calls)
	}
}

// A DMARC failure under p=quarantine (not reject) must still be delivered, just
// classified suspicious — it is not dropped.
func TestInboundDeliversQuarantineFail(t *testing.T) {
	store := &capturingStore{}
	recipientKP := mustKeyPair(t)
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, recipientKP), nil
	}
	auth := fixedAuth{res: &bridge.AuthResult{DMARC: bridge.DMARCFail, DMARCPolicy: bridge.DMARCPolicyQuarantine}}
	h := newInbound(auth, lookup, store.fn, mustKeyPair(t))

	err := h.HandleMessage(context.Background(), "9.9.9.9", "ext@gmail.com", "alice@bridge.localhost", []byte("From: x@gmail.com\r\n\r\nhi"))
	if err != nil {
		t.Fatalf("quarantine-policy failure should be delivered, got %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("expected message stored, got %d", store.calls)
	}
}
