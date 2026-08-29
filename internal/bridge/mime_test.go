package bridge

import (
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/message"
)

var fixedTime = time.Unix(1_700_000_000, 0).UTC()

// TestMIMERoundTrip builds a rich DMCN message (HTML body, an attachment, a reply link) into MIME
// and parses it back, proving the bridge preserves content type, attachments, the subject (incl.
// non-ASCII), and threading across the round trip.
func TestMIMERoundTrip(t *testing.T) {
	msg := &message.PlaintextMessage{
		Subject: "Quarterly report 📊",
		Body:    message.MessageBody{ContentType: "text/html", Content: []byte("<p>See attached.</p>")},
	}
	msg.MessageID[0] = 0x11
	msg.ReplyToID[0] = 0x42
	msg.Attachments = []message.AttachmentRecord{{
		Filename:    "report.pdf",
		ContentType: "application/pdf",
		Content:     []byte("%PDF-1.4 not really a pdf"),
	}}

	raw, err := buildMIME("bridge@bridge.test", "bob@example.com", msg, Audience{}, fixedTime)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	if !strings.Contains(string(raw), "In-Reply-To:") {
		t.Errorf("built message has no In-Reply-To header:\n%s", raw)
	}

	parsed, err := parseInboundMIME(raw)
	if err != nil {
		t.Fatalf("parseInboundMIME: %v", err)
	}
	if parsed.Subject != msg.Subject {
		t.Errorf("subject = %q, want %q", parsed.Subject, msg.Subject)
	}
	// HTML-only mail comes back as a text/plain RENDERING with the original HTML kept as the
	// alternative — Body is what a text-only client (and a trust-gated plain-text peek) reads,
	// so it must never be the markup.
	if parsed.Body.ContentType != "text/plain" || string(parsed.Body.Content) != "See attached." {
		t.Errorf("body = %q (%s), want the rendered text", parsed.Body.Content, parsed.Body.ContentType)
	}
	if len(parsed.Alternatives) != 1 || parsed.Alternatives[0].ContentType != "text/html" ||
		string(parsed.Alternatives[0].Content) != "<p>See attached.</p>" {
		t.Errorf("alternatives = %+v, want the original HTML", parsed.Alternatives)
	}
	if len(parsed.Attachments) != 1 {
		t.Fatalf("attachments = %d, want 1", len(parsed.Attachments))
	}
	if a := parsed.Attachments[0]; a.Filename != "report.pdf" || string(a.Content) != "%PDF-1.4 not really a pdf" {
		t.Errorf("attachment = %q / %q, want report.pdf with its bytes", a.Filename, a.Content)
	}
	// Threading survives: the outbound In-Reply-To (derived from ReplyToID) parses back to a
	// matching non-zero ReplyToID, so the conversation stays linked.
	if parsed.ReplyToID == ([16]byte{}) {
		t.Fatal("In-Reply-To threading lost on round trip")
	}
	// MsgIDList returns the bare msg-id (no angle brackets), so derive from the stripped form.
	if want := deriveID(strings.Trim(mailMsgID(msg.ReplyToID, "bridge.test"), "<>")); parsed.ReplyToID != want {
		t.Errorf("ReplyToID = %x, want %x (consistent derivation)", parsed.ReplyToID, want)
	}
}

// TestParseInboundMIME_PrefersPlain verifies a multipart/alternative (plain + HTML) maps to the
// text/plain body (most compatible), and that a real Message-ID threads.
func TestParseInboundMIME_PrefersPlain(t *testing.T) {
	raw := "From: <ext@gmail.com>\r\n" +
		"To: <alice@bridge.test>\r\n" +
		"Subject: Hi\r\n" +
		"Message-ID: <abc123@gmail.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"b\"\r\n" +
		"\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"plain version\r\n" +
		"--b\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n\r\n" +
		"<b>html version</b>\r\n" +
		"--b--\r\n"

	parsed, err := parseInboundMIME([]byte(raw))
	if err != nil {
		t.Fatalf("parseInboundMIME: %v", err)
	}
	if parsed.Subject != "Hi" {
		t.Errorf("subject = %q, want Hi", parsed.Subject)
	}
	if parsed.Body.ContentType != "text/plain" || strings.TrimSpace(string(parsed.Body.Content)) != "plain version" {
		t.Errorf("body = %q (%s), want the plain alternative", parsed.Body.Content, parsed.Body.ContentType)
	}
	if !parsed.HasIDs || parsed.MessageID != deriveID("abc123@gmail.com") {
		t.Errorf("Message-ID not mapped onto a DMCN ID")
	}
}
