package bridge

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"dmcn.dev/open-dmcn/internal/core/message"
)

// Outbound multipart tests: a DMCN message composed with an HTML alternative must reach a
// legacy MTA as real multipart/alternative (both renderings), and inline images must keep
// their Content-ID + inline disposition so `cid:` references in the HTML resolve in the
// recipient's client instead of showing up as stray attachments.

func htmlMsg() *message.PlaintextMessage {
	return &message.PlaintextMessage{
		Subject:      "Formatted",
		Body:         message.MessageBody{ContentType: "text/plain", Content: []byte("plain version")},
		Alternatives: []message.MessageBody{{ContentType: "text/html", Content: []byte("<p>html <b>version</b></p>")}},
	}
}

// contentTypes returns every Content-Type value in the raw message, in order.
func contentTypes(raw []byte) []string {
	re := regexp.MustCompile(`(?im)^Content-Type:\s*([^;\r\n]+)`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		out = append(out, strings.ToLower(strings.TrimSpace(m[1])))
	}
	return out
}

// TestBuildMIME_AlternativesNoAttachments: plain + HTML and nothing else ⇒ a top-level
// multipart/alternative whose parts are ordered least-rich first (RFC 2046 §5.1.4).
func TestBuildMIME_AlternativesNoAttachments(t *testing.T) {
	raw, err := buildMIME("bridge@bridge.test", "bob@example.com", htmlMsg(), Audience{}, fixedTime)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	got := contentTypes(raw)
	want := []string{"multipart/alternative", "text/plain", "text/html"}
	if len(got) != len(want) {
		t.Fatalf("content types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("content types = %v, want %v", got, want)
		}
	}

	// Both renderings are actually present (quoted-printable encoded, so match loosely).
	parsed, err := parseInboundMIME(raw)
	if err != nil {
		t.Fatalf("parseInboundMIME: %v", err)
	}
	if strings.TrimSpace(string(parsed.Body.Content)) != "plain version" {
		t.Errorf("primary body = %q, want the plain rendering", parsed.Body.Content)
	}
	if len(parsed.Alternatives) != 1 || !strings.Contains(string(parsed.Alternatives[0].Content), "<b>version</b>") {
		t.Errorf("alternatives = %+v, want the HTML rendering", parsed.Alternatives)
	}
}

// TestBuildMIME_AlternativesWithAttachment: the alternative pair nests inside multipart/mixed
// so the attachment sits alongside the body group rather than inside it.
func TestBuildMIME_AlternativesWithAttachment(t *testing.T) {
	msg := htmlMsg()
	msg.Attachments = []message.AttachmentRecord{{
		Filename:    "report.pdf",
		ContentType: "application/pdf",
		Content:     []byte("%PDF-1.4"),
	}}

	raw, err := buildMIME("bridge@bridge.test", "bob@example.com", msg, Audience{}, fixedTime)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	got := contentTypes(raw)
	want := []string{"multipart/mixed", "multipart/alternative", "text/plain", "text/html", "application/pdf"}
	if len(got) != len(want) {
		t.Fatalf("content types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("content types = %v, want %v", got, want)
		}
	}

	parsed, err := parseInboundMIME(raw)
	if err != nil {
		t.Fatalf("parseInboundMIME: %v", err)
	}
	if len(parsed.Alternatives) != 1 {
		t.Fatalf("alternatives = %d, want 1", len(parsed.Alternatives))
	}
	if len(parsed.Attachments) != 1 || parsed.Attachments[0].Filename != "report.pdf" {
		t.Fatalf("attachments = %+v, want report.pdf", parsed.Attachments)
	}
}

// TestBuildMIME_InlineImage: an inline part keeps Content-Disposition: inline and its
// Content-ID, so the HTML body's cid: reference resolves. It must NOT be emitted through
// CreateAttachment, which force-rewrites the disposition to "attachment".
func TestBuildMIME_InlineImage(t *testing.T) {
	msg := htmlMsg()
	msg.Alternatives = []message.MessageBody{{
		ContentType: "text/html",
		Content:     []byte(`<p>see <img src="cid:logo@dmcn"></p>`),
	}}
	msg.Attachments = []message.AttachmentRecord{{
		Filename:    "logo.png",
		ContentType: "image/png",
		Content:     []byte("\x89PNG fake"),
		ContentID:   "logo@dmcn",
		Disposition: "inline",
	}}

	raw, err := buildMIME("bridge@bridge.test", "bob@example.com", msg, Audience{}, fixedTime)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	s := string(raw)
	// go-message canonicalizes the header name ("Content-Id"), so match case-insensitively.
	if !regexp.MustCompile(`(?im)^Content-ID:\s*<logo@dmcn>`).MatchString(s) {
		t.Errorf("inline part has no Content-ID:\n%s", s)
	}
	// The image part must be inline. Guard specifically against the disposition being
	// rewritten to "attachment" for the image (the classification/user attachments in
	// other tests legitimately carry attachment dispositions).
	if regexp.MustCompile(`(?is)Content-Type:\s*image/png.*?Content-Disposition:\s*attachment`).MatchString(s) ||
		regexp.MustCompile(`(?is)Content-Disposition:\s*attachment[^-]*?Content-Type:\s*image/png`).MatchString(s) {
		t.Errorf("inline image was emitted with Content-Disposition: attachment:\n%s", s)
	}
	// The filename rides as the content-type "name" parameter (quoting is the writer's call).
	if !regexp.MustCompile(`(?i)name="?logo\.png"?`).MatchString(s) {
		t.Errorf("inline part lost its filename:\n%s", s)
	}

	parsed, err := parseInboundMIME(raw)
	if err != nil {
		t.Fatalf("parseInboundMIME: %v", err)
	}
	if len(parsed.Attachments) != 1 {
		t.Fatalf("attachments = %d, want the inline image", len(parsed.Attachments))
	}
	a := parsed.Attachments[0]
	if a.ContentID != "logo@dmcn" || a.Disposition != "inline" {
		t.Errorf("round-tripped inline part = cid %q / disposition %q, want logo@dmcn / inline", a.ContentID, a.Disposition)
	}
	if string(a.Content) != "\x89PNG fake" {
		t.Errorf("inline image bytes changed: %q", a.Content)
	}
}

// TestDKIMVerifiesMultipartAlternative: DKIM signs the assembled body, so nesting the body
// in multipart/alternative (with an inline image part) must not disturb relaxed body
// canonicalization. Deliverability depends on this — an HTML send that fails DKIM would
// land in spam exactly when the formatting works.
func TestDKIMVerifiesMultipartAlternative(t *testing.T) {
	signer, _, err := GenerateDKIMKey("rsa")
	if err != nil {
		t.Fatalf("GenerateDKIMKey: %v", err)
	}
	const domain, selector = "bridge.test", "alt"
	ds, err := NewDKIMSigner(domain, selector, signer)
	if err != nil {
		t.Fatalf("NewDKIMSigner: %v", err)
	}

	msg := htmlMsg()
	msg.Alternatives = []message.MessageBody{{
		ContentType: "text/html",
		Content:     []byte(`<p>hi <img src="cid:logo@dmcn"></p>`),
	}}
	msg.Attachments = []message.AttachmentRecord{{
		Filename:    "logo.png",
		ContentType: "image/png",
		Content:     []byte("\x89PNG fake"),
		ContentID:   "logo@dmcn",
		Disposition: "inline",
	}}

	raw, err := buildMIME("alice@"+domain, "bob@example.com", msg, Audience{}, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	signed, err := ds.Sign(raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	txt, err := dkimPublicTXT(signer.Public())
	if err != nil {
		t.Fatalf("dkimPublicTXT: %v", err)
	}
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(signed), &dkim.VerifyOptions{
		LookupTXT: txtLookupFor(t, domain, selector, txt),
	})
	if err != nil {
		t.Fatalf("VerifyWithOptions: %v", err)
	}
	if len(verifs) != 1 || verifs[0].Err != nil {
		t.Fatalf("multipart/alternative message did not verify: %+v", verifs)
	}
}

// TestBuildMIME_PlainOnlyShapeUnchanged pins the pre-HTML output shapes: a plain message with
// no attachments stays a single part (no multipart wrapper at all), and plain + attachment
// stays multipart/mixed with a single inline body. Regression guard — the alternatives work
// must not restructure ordinary mail.
func TestBuildMIME_PlainOnlyShapeUnchanged(t *testing.T) {
	plain := &message.PlaintextMessage{
		Subject: "Plain",
		Body:    message.MessageBody{ContentType: "text/plain", Content: []byte("just text")},
	}
	raw, err := buildMIME("bridge@bridge.test", "bob@example.com", plain, Audience{}, fixedTime)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	if got := contentTypes(raw); len(got) != 1 || got[0] != "text/plain" {
		t.Errorf("plain-only content types = %v, want [text/plain]", got)
	}

	plain.Attachments = []message.AttachmentRecord{{Filename: "a.txt", ContentType: "text/plain", Content: []byte("x")}}
	raw, err = buildMIME("bridge@bridge.test", "bob@example.com", plain, Audience{}, fixedTime)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	got := contentTypes(raw)
	want := []string{"multipart/mixed", "text/plain", "text/plain"}
	if len(got) != len(want) {
		t.Fatalf("plain+attachment content types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plain+attachment content types = %v, want %v", got, want)
		}
	}
}
