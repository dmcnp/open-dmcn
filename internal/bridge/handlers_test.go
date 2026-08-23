package bridge_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// These tests exercise the inbound/outbound handler logic directly, with all
// dependencies stubbed — no libp2p, no network — so the error and contract paths
// the slow end-to-end integration test skips are covered fast.

const (
	// tBridgeAddr stands in for the bridge's libp2p peer ID. A bridge has no email address, so
	// this field is informational — a fixture using an email would model a shape the protocol
	// no longer has.
	tBridgeAddr   = "12D3KooWBridgeTestPeerIDFixture0000000000000000"
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

// splitSealedToBridge builds the SPLIT form of the same envelope — header and body sealed
// separately, with the sender signature over the header. This is what a browser actually produces,
// and what the outbound path could not read until Aug 2026: message.Decrypt only understands the
// older single-blob form, so every real outbound message failed AEAD authentication. It went
// unnoticed because nothing could discover the bridge in order to send to it.
func splitSealedToBridge(t *testing.T, senderKP, bridgeKP *identity.IdentityKeyPair, sender, recipient, body string) *message.EncryptedEnvelope {
	t.Helper()
	msg, err := message.NewPlaintextMessage(sender, recipient, "Re: Hello", body, senderKP.Ed25519Public)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	sh, content, err := message.Split(msg, senderKP.Ed25519Private)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	env, err := message.EncryptSplit(sh, content,
		[]message.RecipientInfo{{DeviceID: senderKP.DeviceID, X25519Pub: bridgeKP.X25519Public}},
		senderKP.Ed25519Private)
	if err != nil {
		t.Fatalf("encrypt split: %v", err)
	}
	if !env.IsSplit() {
		t.Fatal("built a non-split envelope; this test would not cover what it claims to")
	}
	return env
}

// TestOutboundDeliversASplitEnvelope is the regression for that bug: the shape a browser sends
// must be deliverable, and its sender signature — which covers the HEADER, not the plaintext —
// must be verified rather than skipped.
func TestOutboundDeliversASplitEnvelope(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	const body = "sent from a browser"
	env := splitSealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", body)
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
	if len(deliverer.Messages) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliverer.Messages))
	}
	got := deliverer.Messages[0]
	if got.To != "ext@gmail.com" {
		t.Errorf("delivered to %q", got.To)
	}
	// The body lives in the separately-sealed half, so a header-only decrypt would silently
	// deliver an empty message rather than fail.
	if !strings.Contains(got.Body, body) {
		t.Errorf("body did not survive the split round trip: %q", got.Body)
	}
}

// TestOutboundRejectsATamperedSplitBody keeps the verification honest across the reassembly: the
// sender signs the header, and the header commits to the body — so swapping the body must fail.
func TestOutboundRejectsATamperedSplitBody(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := splitSealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "original")
	other := splitSealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "swapped in")
	env.EncryptedBody = other.EncryptedBody
	env.BodyNonce = other.BodyNonce
	env.BodyTag = other.BodyTag

	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, &bridge.StubSMTPDeliverer{}, bridgeKP)

	if _, err := h.HandleEnvelope(context.Background(), env); err == nil {
		t.Fatal("a swapped body was accepted — the header's commitment to the body is not being checked")
	}
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

// TestSplitEnvelopeYieldsAWorkingReceipt is the regression for a bug that only showed on the
// happy path: a message was delivered to SMTP, and then the delivery receipt was silently dropped
// because the code that builds it used the legacy-only decrypt. Delivery succeeded, the sender
// was never told, and the log line looked like a decryption failure on a message that had just
// been decrypted fine moments earlier.
//
// It tests decryptForBridge directly because that is the shared path both HandleEnvelope and
// sendReceipt take — the bug was one of them not using it.
func TestSplitEnvelopeYieldsAWorkingReceipt(t *testing.T) {
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := splitSealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "body")

	// The delivery path reads it...
	h := newOutbound(func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, senderKP), nil
	}, &bridge.StubSMTPDeliverer{}, bridgeKP)
	if _, err := h.HandleEnvelope(context.Background(), env); err != nil {
		t.Fatalf("delivery: %v", err)
	}

	// ...and so must the receipt path, from the SAME envelope. Anything that can be delivered
	// can be acknowledged; if these two ever disagree, the sender stops hearing back.
	pt, err := bridge.DecryptForBridgeForTest(env, bridgeKP)
	if err != nil {
		t.Fatalf("the receipt path could not read an envelope the delivery path just read: %v", err)
	}
	if pt.SenderAddress != "alice@dmcn.localhost" {
		t.Errorf("sender address = %q, so the receipt would be addressed wrongly", pt.SenderAddress)
	}
}

// TestInboundAttributesTheLegacySender is what a mail client actually shows. Inbound mail was
// attributed to the bridge, whose "address" is now a libp2p peer ID — so every bridged message
// appeared to come from the same unreadable correspondent, and who actually wrote survived only
// inside the classification record.
//
// The bridge signs the message, so this address is a claim rather than a proof. The attestation is
// what backs it: a recipient checks the bridge's credential and its SPF/DKIM/DMARC verdict for
// this exact address before the name means anything. Attributing the mail to the bridge instead
// discards the identity the bridge just verified.
func TestInboundAttributesTheLegacySender(t *testing.T) {
	recipientKP := mustKeyPair(t)
	bridgeKP := mustKeyPair(t)
	var delivered *message.PlaintextMessage

	h := bridge.NewInboundHandler(bridge.InboundConfig{
		BridgeKP:     bridgeKP,
		BridgeAddr:   tBridgeAddr,
		AuthVerifier: &bridge.StubAuthVerifier{},
		Lookup: func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
			return recordFor(addr, recipientKP), nil
		},
		Deliver: func(_ context.Context, _ *identity.IdentityRecord, env *message.EncryptedEnvelope) error {
			sh, err := message.DecryptHeader(env, recipientKP.X25519Private, recipientKP.X25519Public)
			if err != nil {
				return err
			}
			delivered = &message.PlaintextMessage{
				SenderAddress:    sh.Header.SenderAddress,
				RecipientAddress: sh.Header.RecipientAddress,
			}
			return nil
		},
		BridgeDomain: "bridge.localhost",
		DMCNDomain:   "dmcn.localhost",
		Log:          testLog(),
	})

	raw := []byte("From: someone@gmail.com\r\nSubject: hello\r\n\r\nbody\r\n")
	if err := h.HandleMessage(context.Background(), "203.0.113.9", "someone@gmail.com", "alice@bridge.localhost", raw); err != nil {
		t.Fatalf("inbound: %v", err)
	}
	if delivered == nil {
		t.Fatal("nothing was delivered")
	}
	if delivered.SenderAddress != "someone@gmail.com" {
		t.Errorf("sender = %q, want the legacy sender — a peer ID or bridge address tells the reader nothing",
			delivered.SenderAddress)
	}
}

// TestOnlyFailuresProduceANotice: a success receipt per message would put a second message in the
// sender's own mailbox for every one they write. Email has never worked that way — a DSN is for
// non-delivery — and the signed success receipt still exists on the audit trail regardless.
func TestOnlyFailuresProduceANotice(t *testing.T) {
	if !bridge.ShouldNotifySenderForTest(&bridge.BridgeDeliveryReceipt{Success: false}) {
		t.Error("a delivery FAILURE produced no notice — the sender would never learn about it")
	}
	if bridge.ShouldNotifySenderForTest(&bridge.BridgeDeliveryReceipt{Success: true}) {
		t.Error("a delivery SUCCESS produced a notice — that is a second message per message sent")
	}
	if bridge.ShouldNotifySenderForTest(nil) {
		t.Error("no receipt produced a notice")
	}
}

// TestFailureNoticeIsReadableWithoutTheAttachment covers the other half of the complaint: the body
// said "Message delivery receipt attached." and nothing else, so the reader had to open a binary
// blob to learn what had happened.
func TestFailureNoticeIsReadableWithoutTheAttachment(t *testing.T) {
	body := bridge.DeliveryFailureBodyForTest(&bridge.BridgeDeliveryReceipt{
		RecipientEmail: "someone@example.com",
		Success:        false,
		ErrorDetail:    "550 mailbox unavailable",
		DeliveredAt:    time.Now().UTC(),
	}, "Quarterly numbers")

	for _, want := range []string{"someone@example.com", "Quarterly numbers", "550 mailbox unavailable"} {
		if !strings.Contains(body, want) {
			t.Errorf("the notice does not mention %q:\n%s", want, body)
		}
	}
}

// TestFailureNoticeComesFromMailerDaemon: the bridge has no mailbox, and a libp2p peer ID in the
// From line is meaningless to a reader. MAILER-DAEMON is what mail users have recognised as "the
// system, not a person" for decades, and it is a reserved local-part so nobody can register it.
func TestFailureNoticeComesFromMailerDaemon(t *testing.T) {
	got := bridge.MailerDaemonAddressForTest("merten.vg")
	if got != "mailer-daemon@merten.vg" {
		t.Errorf("notice sender = %q, want mailer-daemon@merten.vg", got)
	}
	if strings.HasPrefix(got, "12D3Koo") {
		t.Error("the notice is addressed from a peer ID")
	}
}
