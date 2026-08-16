package bridge_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// These tests exercise the inbound/outbound handler logic directly, with all
// dependencies stubbed — no libp2p, no network — so the error and contract paths
// the slow end-to-end integration test skips are covered fast.

const (
	tBridgeAddr   = "bridge@bridge.localhost"
	tBridgeDomain = "bridge.localhost"
	tDMCNDomain   = "dmcn.localhost"
)

func mustKeyPair(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return kp
}

func testLog() logr.Logger { return logr.With(logr.M("test", true)) }

// recordFor builds a minimal identity record exposing only the public keys the
// handlers consume from a registry lookup.
func recordFor(addr string, kp *identity.IdentityKeyPair) *identity.IdentityRecord {
	return &identity.IdentityRecord{
		Address:       addr,
		Ed25519Public: kp.Ed25519Public,
		X25519Public:  kp.X25519Public,
	}
}

// --- inbound ----------------------------------------------------------------

// erroringAuth fails authentication verification.
type erroringAuth struct{}

func (erroringAuth) Verify(context.Context, string, string, []byte) (*bridge.AuthResult, error) {
	return nil, errors.New("dns timeout")
}

func passingAuth() *bridge.StubAuthVerifier {
	return &bridge.StubAuthVerifier{DefaultSPF: bridge.SPFPass, DefaultDKIM: bridge.DKIMPass, DefaultDMARC: bridge.DMARCPass}
}

// capturingStore records what the inbound handler delivered (a DeliverFunc).
type capturingStore struct {
	mu    sync.Mutex
	calls int
	env   *message.EncryptedEnvelope
}

func (c *capturingStore) fn(_ context.Context, _ *identity.IdentityRecord, env *message.EncryptedEnvelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.env = env
	return nil
}

func newInbound(auth bridge.AuthVerifier, lookup bridge.LookupFunc, deliver bridge.DeliverFunc, kp *identity.IdentityKeyPair) *bridge.InboundHandler {
	return bridge.NewInboundHandler(bridge.InboundConfig{
		BridgeKP:     kp,
		BridgeAddr:   tBridgeAddr,
		AuthVerifier: auth,
		Lookup:       lookup,
		Deliver:      deliver,
		BridgeDomain: tBridgeDomain,
		DMCNDomain:   tDMCNDomain,
		Log:          testLog(),
	})
}

func TestInboundAuthError(t *testing.T) {
	store := &capturingStore{}
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) {
		t.Fatal("lookup must not run when auth fails")
		return nil, nil
	}
	h := newInbound(erroringAuth{}, lookup, store.fn, mustKeyPair(t))

	err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "alice@bridge.localhost", []byte("hi"))
	if err == nil || !strings.Contains(err.Error(), "auth verify") {
		t.Fatalf("expected auth verify error, got %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("nothing should be stored on auth failure, got %d", store.calls)
	}
}

func TestInboundRecipientNotFound(t *testing.T) {
	store := &capturingStore{}
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return nil, errors.New("not in DHT")
	}
	h := newInbound(passingAuth(), lookup, store.fn, mustKeyPair(t))

	err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "alice@bridge.localhost", []byte("hi"))
	if !errors.Is(err, bridge.ErrRecipientNotFound) {
		t.Fatalf("expected ErrRecipientNotFound, got %v", err)
	}
	if store.calls != 0 {
		t.Fatalf("nothing should be stored for an unknown recipient, got %d", store.calls)
	}
}

// Happy path without any network: the stored envelope must decrypt for the
// recipient, verify as bridge-signed, carry the original body, and include a
// valid bridge-signed classification record.
func TestInboundStoresDecryptableEnvelope(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	recipientKP := mustKeyPair(t)
	const body = "Hello Alice from legacy email!"

	var lookedUp string
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		lookedUp = addr
		return recordFor(addr, recipientKP), nil
	}
	store := &capturingStore{}
	h := newInbound(passingAuth(), lookup, store.fn, bridgeKP)

	if err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "alice@bridge.localhost", []byte(body)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	// The bridge address mapping must derive the DMCN recipient from the domains.
	if lookedUp != "alice@dmcn.localhost" {
		t.Fatalf("looked up %q, want alice@dmcn.localhost", lookedUp)
	}
	if store.calls != 1 || store.env == nil {
		t.Fatalf("expected exactly one delivered envelope, got %d", store.calls)
	}

	// The bridge now produces a split (v2) envelope — the same format clients and
	// the durable mailbox use — so decrypt via the split header/body path.
	if !store.env.IsSplit() {
		t.Fatal("bridge envelope must be split (v2)")
	}
	sh, err := message.DecryptHeader(store.env, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt header (verifies bridge signature): %v", err)
	}
	content, err := message.DecryptBody(store.env, &sh.Header, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	if string(content.Body.Content) != body {
		t.Fatalf("body: got %q, want %q", content.Body.Content, body)
	}
	if len(content.Attachments) == 0 {
		t.Fatal("expected classification attachment")
	}
	att := content.Attachments[0]
	if att.ContentType != bridge.ClassificationContentType {
		t.Fatalf("attachment type: %s", att.ContentType)
	}
	classRec, err := bridge.UnmarshalClassificationRecord(att.Content)
	if err != nil {
		t.Fatalf("unmarshal classification: %v", err)
	}
	if err := classRec.Verify(); err != nil {
		t.Fatalf("classification signature invalid: %v", err)
	}
	if classRec.SMTPFrom != "ext@gmail.com" {
		t.Fatalf("classification smtp_from: %q", classRec.SMTPFrom)
	}
}

// --- outbound ---------------------------------------------------------------

// failingDeliverer fails SMTP delivery with a fixed error.
type failingDeliverer struct{ err error }

func (d failingDeliverer) Deliver(context.Context, string, string, *message.PlaintextMessage) error {
	return d.err
}

func newOutbound(lookup bridge.LookupFunc, deliverer bridge.SMTPDeliverer, kp *identity.IdentityKeyPair) *bridge.OutboundHandler {
	return bridge.NewOutboundHandler(bridge.OutboundConfig{
		BridgeKP:     kp,
		BridgeAddr:   tBridgeAddr,
		Deliverer:    deliverer,
		Lookup:       lookup,
		BridgeDomain: tBridgeDomain,
		DMCNDomain:   tDMCNDomain,
		Log:          testLog(),
	})
}

// sealedToBridge builds an envelope from sender to recipient, encrypted to the
// bridge's X25519 key, as a DMCN client would when mailing a legacy address.
func sealedToBridge(t *testing.T, senderKP, bridgeKP *identity.IdentityKeyPair, sender, recipient, body string) *message.EncryptedEnvelope {
	t.Helper()
	msg, err := message.NewPlaintextMessage(sender, recipient, "Re: Hello", body, senderKP.Ed25519Public)
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

func TestOutboundRejectsUndecryptableEnvelope(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	otherKP := mustKeyPair(t) // envelope sealed to this, NOT the bridge

	env := sealedToBridge(t, senderKP, otherKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(context.Context, string) (*identity.IdentityRecord, error) {
		t.Fatal("must not reach registry lookup before decrypt succeeds")
		return nil, nil
	}, deliverer, bridgeKP)

	_, err := h.HandleEnvelope(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("expected decrypt error, got %v", err)
	}
	if len(deliverer.Messages) != 0 {
		t.Fatal("must not deliver an envelope it cannot decrypt")
	}
}

func TestOutboundSenderNotFound(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(context.Context, string) (*identity.IdentityRecord, error) {
		return nil, errors.New("not in DHT")
	}, deliverer, bridgeKP)

	receipt, err := h.HandleEnvelope(context.Background(), env)
	if !errors.Is(err, bridge.ErrSenderNotFound) {
		t.Fatalf("expected ErrSenderNotFound, got %v", err)
	}
	if receipt != nil {
		t.Fatal("no receipt should be issued when the sender is unknown")
	}
	if len(deliverer.Messages) != 0 {
		t.Fatal("must not deliver for an unknown sender")
	}
}

func TestOutboundRejectsNonLegacyRecipient(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	// Recipient on the DMCN domain is NOT a legacy email address.
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "bob@dmcn.localhost", "hi")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP)

	_, err := h.HandleEnvelope(context.Background(), env)
	if !errors.Is(err, bridge.ErrNotLegacyAddress) {
		t.Fatalf("expected ErrNotLegacyAddress, got %v", err)
	}
	if len(deliverer.Messages) != 0 {
		t.Fatal("must not deliver to a non-legacy recipient")
	}
}

// Contract: on delivery failure the handler still returns a SIGNED receipt
// (Success=false, ErrorDetail set) AND surfaces the delivery error. Both the
// receipt and the error are non-nil — a subtle dual return worth locking down.
func TestOutboundDeliveryFailureReturnsSignedReceiptAndError(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
	deliverer := failingDeliverer{err: errors.New("mailbox full")}
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP)

	receipt, err := h.HandleEnvelope(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "mailbox full") {
		t.Fatalf("expected the delivery error surfaced, got %v", err)
	}
	if receipt == nil {
		t.Fatal("expected a receipt even on delivery failure")
	}
	if receipt.Success {
		t.Fatal("receipt should report failure")
	}
	if !strings.Contains(receipt.ErrorDetail, "mailbox full") {
		t.Fatalf("receipt error detail: %q", receipt.ErrorDetail)
	}
	if err := receipt.Verify(bridgeKP.Ed25519Public); err != nil {
		t.Fatalf("failure receipt must still be bridge-signed: %v", err)
	}
}

func TestOutboundDeliversAndSignsReceipt(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	const body = "Hello from DMCN!"
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", body)
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, deliverer, bridgeKP)

	receipt, err := h.HandleEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !receipt.Success {
		t.Fatalf("expected success, detail=%q", receipt.ErrorDetail)
	}
	if err := receipt.Verify(bridgeKP.Ed25519Public); err != nil {
		t.Fatalf("receipt signature invalid: %v", err)
	}
	if len(deliverer.Messages) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliverer.Messages))
	}
	got := deliverer.Messages[0]
	// Sender is rewritten to the bridge domain so legacy MTAs accept it.
	if got.From != "alice@bridge.localhost" {
		t.Fatalf("smtp from: %q", got.From)
	}
	if got.To != "ext@gmail.com" || got.Body != body {
		t.Fatalf("delivered: to=%q body=%q", got.To, got.Body)
	}
}
