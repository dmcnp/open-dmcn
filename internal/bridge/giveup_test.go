package bridge_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// deferringDeliverer is a remote server that keeps saying "come back later".
type deferringDeliverer struct{ calls int }

func (d *deferringDeliverer) Deliver(context.Context, string, string, *message.PlaintextMessage, bridge.Audience) error {
	d.calls++
	return fmt.Errorf("%w: 451 greylisted", bridge.ErrDeliveryDeferred)
}

func newOutboundWith(t *testing.T, lookup bridge.LookupFunc, deliverer bridge.SMTPDeliverer, kp *identity.IdentityKeyPair, audit bridge.AuditLog, rateLimit int) *bridge.OutboundHandler {
	t.Helper()
	return bridge.NewOutboundHandler(bridge.OutboundConfig{
		BridgeKP:          kp,
		BridgeAddr:        tBridgeAddr,
		Deliverer:         deliverer,
		Lookup:            lookup,
		BridgeDomain:      tBridgeDomain,
		DMCNDomain:        tDMCNDomain,
		OutboundRateLimit: rateLimit,
		Audit:             audit,
		Log:               testLog(),
	})
}

// A deferral from the remote server is not a verdict: the attempt asks to be retried, and when
// the bridge finally gives up the verified sender gets a signed notice saying how long we tried.
func TestDeferredDeliveryIsRetriedThenGivenUpWithNotice(t *testing.T) {
	bridgeKP, senderKP := mustKeyPair(t), mustKeyPair(t)
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
	audit := &capturingAudit{}
	h := newOutboundWith(t, registryOwning(senderKP), &deferringDeliverer{}, bridgeKP, audit, 0)

	a := h.Attempt(context.Background(), env)
	if !a.Retry || a.Receipt != nil || !errors.Is(a.Err, bridge.ErrDeliveryDeferred) {
		t.Fatalf("attempt = %+v, want a retry with no verdict", a)
	}

	receipt := h.Abandon(a, 5*24*time.Hour)
	if receipt == nil || receipt.Success {
		t.Fatalf("expected a failure receipt, got %+v", receipt)
	}
	if receipt.RecipientEmail != "ext@gmail.com" || !strings.Contains(receipt.ErrorDetail, "after 5 days") {
		t.Fatalf("receipt = %+v, want one for ext@gmail.com saying how long we tried", receipt)
	}
	if err := receipt.Verify(bridgeKP.Ed25519Public); err != nil {
		t.Fatalf("receipt signature: %v", err)
	}
	if audit.byAction("outbound.expire") == nil {
		t.Fatal("giving up left no audit record")
	}
}

// A retry after a deferral is the same message: the sending limits counted it once, and do not
// refuse or count it again.
func TestRetryAfterDeferralIsNotCountedAgain(t *testing.T) {
	bridgeKP, senderKP := mustKeyPair(t), mustKeyPair(t)
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
	d := &deferringDeliverer{}
	h := newOutboundWith(t, registryOwning(senderKP), d, bridgeKP, nil, 1) // one message an hour

	for i := 0; i < 3; i++ {
		if a := h.Attempt(context.Background(), env); errors.Is(a.Err, bridge.ErrOutboundRateLimited) {
			t.Fatalf("attempt %d was rate limited: the retry was counted again", i+1)
		}
	}
	if d.calls != 3 {
		t.Fatalf("the remote server was tried %d times, want 3", d.calls)
	}
}

// Nobody is told unless their signing key was checked: an envelope the bridge cannot open names
// no one, a forgery names someone who did not write it, and a sender whose record could not be
// fetched was never verified. Each is still in the audit trail.
func TestAbandonTellsOnlyAVerifiedSender(t *testing.T) {
	bridgeKP, senderKP, otherKP := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	audit := &capturingAudit{}
	h := newOutboundWith(t, registryOwning(senderKP), &bridge.StubSMTPDeliverer{}, bridgeKP, audit, 0)
	noRecord := newOutboundWith(t, func(context.Context, string) (*identity.IdentityRecord, error) {
		return nil, errors.New("fleet unreachable")
	}, &bridge.StubSMTPDeliverer{}, bridgeKP, audit, 0)

	for _, tc := range []struct {
		name  string
		h     *bridge.OutboundHandler
		env   *message.EncryptedEnvelope
		want  error
		retry bool
	}{
		{"undecryptable", h, sealedToBridge(t, senderKP, otherKP, "alice@dmcn.localhost", "ext@gmail.com", "hi"), bridge.ErrUndecryptable, false},
		{"forged sender", h, impersonatingEnvelope(t, otherKP, bridgeKP, "ceo@dmcn.localhost", "ext@gmail.com"), bridge.ErrSenderKeyMismatch, true},
		{"sender record unavailable", noRecord, sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi"), bridge.ErrSenderNotFound, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.h.Attempt(context.Background(), tc.env)
			if !errors.Is(a.Err, tc.want) || a.Retry != tc.retry {
				t.Fatalf("attempt = (retry %v, %v), want (retry %v, %v)", a.Retry, a.Err, tc.retry, tc.want)
			}
			if r := tc.h.Abandon(a, time.Hour); r != nil {
				t.Fatalf("a notice went out for a sender the bridge never verified: %+v", r)
			}
		})
	}
	if audit.byAction("outbound.drop") == nil || audit.byAction("outbound.expire") == nil {
		t.Fatal("a silent drop or expiry left no audit record")
	}
}

// A refusal no retry can change is final on the first attempt, is audited, and tells the sender
// what went wrong rather than how long we tried.
func TestPermanentRefusalsExplainThemselves(t *testing.T) {
	bridgeKP, senderKP := mustKeyPair(t), mustKeyPair(t)

	for _, tc := range []struct {
		name, sender, recipient string
		want                    error
		notice                  string
	}{
		{"unserved sender domain", "alice@elsewhere.example", "ext@gmail.com", bridge.ErrSenderNotAuthorized, "Your address is not one this service sends ordinary email for."},
		{"recipient on this service", "alice@dmcn.localhost", "bob@dmcn.localhost", bridge.ErrNotLegacyAddress, "That address belongs to this service, so the message has to be sent to it directly, not as ordinary email."},
		{"header injection", "alice@dmcn.localhost", "ext@gmail.com\r\nBcc: hidden@gmail.com", bridge.ErrUnsafeHeader, "The subject or an address contains characters that email does not allow."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &capturingAudit{}
			h := newOutboundWith(t, registryOwning(senderKP), &bridge.StubSMTPDeliverer{}, bridgeKP, audit, 0)
			a := h.Attempt(context.Background(), sealedToBridge(t, senderKP, bridgeKP, tc.sender, tc.recipient, "hi"))
			if !errors.Is(a.Err, tc.want) || a.Retry {
				t.Fatalf("attempt = (retry %v, %v), want a final %v", a.Retry, a.Err, tc.want)
			}
			receipt := h.Abandon(a, 5*24*time.Hour)
			if receipt == nil || receipt.Success || receipt.ErrorDetail != tc.notice {
				t.Fatalf("receipt = %+v, want a failure saying %q", receipt, tc.notice)
			}
			if audit.byAction("outbound.drop") == nil {
				t.Fatal("the drop left no audit record")
			}
		})
	}
}

// A sender who rotates their key while their message waits for a retry still sent it: the retry
// is checked against the key the first attempt verified, not refused as a forgery.
func TestKeyRotationDuringARetryIsNotAForgery(t *testing.T) {
	bridgeKP, oldKP, newKP := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	current := oldKP
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, current), nil
	}
	d := &deferringDeliverer{}
	h := newOutboundWith(t, lookup, d, bridgeKP, nil, 0)
	env := sealedToBridge(t, oldKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")

	if a := h.Attempt(context.Background(), env); !a.Retry || a.Sender == nil {
		t.Fatalf("first attempt = %+v, want a verified sender and a retry", a)
	}
	current = newKP // alice rotates her key
	a := h.Attempt(context.Background(), env)
	if errors.Is(a.Err, bridge.ErrSenderKeyMismatch) {
		t.Fatal("a message alice really sent became a forgery when she rotated her key")
	}
	if d.calls != 2 {
		t.Fatalf("the retry did not reach the remote server (calls %d)", d.calls)
	}
}
