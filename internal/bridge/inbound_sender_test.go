package bridge_test

import (
	"context"
	"strings"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// deliverInbound runs one inbound message through the handler and returns the decrypted
// signed header plus the message content.
func deliverInbound(t *testing.T, envelopeFrom string, raw string) (*message.SignedHeader, *message.MessageContent) {
	t.Helper()
	bridgeKP := mustKeyPair(t)
	recipientKP := mustKeyPair(t)
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, recipientKP), nil
	}
	store := &capturingStore{}
	h := newInbound(passingAuth(), lookup, store.fn, bridgeKP)

	if err := h.HandleMessage(context.Background(), "1.2.3.4", envelopeFrom, "alice@bridge.localhost", []byte(raw)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if store.env == nil {
		t.Fatal("nothing delivered")
	}
	sh, err := message.DecryptHeader(store.env, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt header: %v", err)
	}
	content, err := message.DecryptBody(store.env, &sh.Header, recipientKP.X25519Private, recipientKP.X25519Public)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	return sh, content
}

// A bulk sender relays through a provider: the SMTP envelope sender is a per-message VERP
// bounce address, while the From header carries the identity the mail actually presents (and
// the one the bridge authenticates under DMARC). The recipient must see the From address —
// otherwise every message from the sender looks like a brand-new correspondent that can never
// be allowlisted. The envelope sender is still recorded, signed, in the classification.
func TestInboundSenderIsHeaderFrom(t *testing.T) {
	const verp = "010001a0465134b5-b6032115-35ad-4041-9aa2-6230f9294d46-000000@amazonses.com"
	raw := "From: Reddit <noreply@redditmail.com>\r\n" +
		"To: <alice@bridge.localhost>\r\n" +
		"Subject: Disabled and will be deleted\r\n" +
		"\r\n" +
		"body text\r\n"

	sh, content := deliverInbound(t, verp, raw)

	if sh.Header.SenderAddress != "noreply@redditmail.com" {
		t.Fatalf("sender_address = %q, want the From-header address", sh.Header.SenderAddress)
	}
	classRec, err := bridge.UnmarshalClassificationRecord(content.Attachments[0].Content)
	if err != nil {
		t.Fatalf("unmarshal classification: %v", err)
	}
	if classRec.SMTPFrom != verp {
		t.Fatalf("classification smtp_from = %q, want the envelope sender (it must not be lost)", classRec.SMTPFrom)
	}
}

// The From header's display name rides along in the signed header, so the reader can show
// "Reddit" next to the address instead of an opaque bounce address. It is sanitized by
// message.Split before signing.
func TestInboundCarriesDisplayName(t *testing.T) {
	raw := "From: Reddit <noreply@redditmail.com>\r\n" +
		"To: <alice@bridge.localhost>\r\n" +
		"Subject: Digest\r\n" +
		"\r\n" +
		"body text\r\n"

	sh, _ := deliverInbound(t, "bounce@amazonses.com", raw)

	if sh.Header.SenderDisplay != "Reddit" {
		t.Fatalf("sender_display = %q, want the From display name", sh.Header.SenderDisplay)
	}
	if sh.Header.SenderAddress != "noreply@redditmail.com" {
		t.Fatalf("sender_address = %q", sh.Header.SenderAddress)
	}
	if err := sh.Verify(); err != nil {
		t.Fatalf("the header signature must cover the display name: %v", err)
	}
}

// An RFC 2047 encoded-word name decodes to real text rather than reaching the reader as
// "=?utf-8?B?…?=" — the encoding is a transport detail, not part of the name.
func TestInboundDecodesEncodedDisplayName(t *testing.T) {
	raw := "From: =?utf-8?B?Wm/DqyBNw7xsbGVy?= <zoe@example.test>\r\n" +
		"To: <alice@bridge.localhost>\r\n" +
		"Subject: Hi\r\n" +
		"\r\n" +
		"body\r\n"

	sh, _ := deliverInbound(t, "zoe@example.test", raw)

	if sh.Header.SenderDisplay != "Zoë Müller" {
		t.Fatalf("sender_display = %q, want the decoded name", sh.Header.SenderDisplay)
	}
}

// A display name that carries an address of its own is the oldest phishing trick there is
// ("PayPal Security <security@paypal.com>" in the NAME, a hostile address behind it). It is
// dropped rather than shown; the real address is displayed either way. A name that merely
// repeats the address is dropped as noise.
func TestInboundDropsAddressShapedDisplayName(t *testing.T) {
	for _, name := range []string{`"PayPal Security <security@paypal.com>"`, `"attacker@evil.test"`} {
		raw := "From: " + name + " <attacker@evil.test>\r\n" +
			"To: <alice@bridge.localhost>\r\n" +
			"Subject: Verify your account\r\n" +
			"\r\n" +
			"body\r\n"

		sh, _ := deliverInbound(t, "attacker@evil.test", raw)

		if sh.Header.SenderDisplay != "" {
			t.Fatalf("sender_display = %q for From name %s, want it dropped", sh.Header.SenderDisplay, name)
		}
	}
}

// With no usable From header the envelope sender remains the only identity there is.
func TestInboundSenderFallsBackToEnvelope(t *testing.T) {
	raw := "To: <alice@bridge.localhost>\r\n" +
		"Subject: No From header\r\n" +
		"\r\n" +
		"body text\r\n"

	sh, _ := deliverInbound(t, "ext@gmail.com", raw)

	if sh.Header.SenderAddress != "ext@gmail.com" {
		t.Fatalf("sender_address = %q, want the envelope sender", sh.Header.SenderAddress)
	}
}

// An HTML-only legacy message arrives with a readable text/plain body (what the trust-gated
// plain-text peek shows for a sender you have not trusted yet) and the original HTML as the
// alternative for the trusted-sender render path.
func TestInboundHTMLOnlyDeliversRenderedText(t *testing.T) {
	raw := "From: Reddit <noreply@redditmail.com>\r\n" +
		"To: <alice@bridge.localhost>\r\n" +
		"Subject: Digest\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><head><style>.x{color:red}</style></head><body><p>Your account will be deleted.</p></body></html>\r\n"

	_, content := deliverInbound(t, "bounce@amazonses.com", raw)

	if content.Body.ContentType != "text/plain" {
		t.Fatalf("body content type = %q, want text/plain", content.Body.ContentType)
	}
	if got := strings.TrimSpace(string(content.Body.Content)); got != "Your account will be deleted." {
		t.Fatalf("body = %q, want the rendered text", got)
	}
	if len(content.Alternatives) != 1 || content.Alternatives[0].ContentType != "text/html" {
		t.Fatalf("alternatives = %+v, want the original HTML", content.Alternatives)
	}
}
