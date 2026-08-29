package bridge

import (
	"strings"
	"testing"
)

// TestHTMLToText covers what real HTML mail is made of: a full document with a head, a
// table layout, links, entities, and images — the shape that used to reach the reader as
// raw markup because the message carried no text/plain part.
func TestHTMLToText(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "paragraphs and line breaks",
			html: "<p>Hello there</p><p>Second<br>line</p>",
			want: "Hello there\n\nSecond\nline",
		},
		{
			name: "head, style and script content never leak",
			html: `<!DOCTYPE html><html><head><title>Digest</title>` +
				`<style>.a{color:red}</style></head><body><script>alert(1)</script><p>Body text</p></body></html>`,
			want: "Body text",
		},
		{
			name: "layout table becomes lines",
			html: "<table><tr><td>First cell</td></tr><tr><td>Second cell</td></tr></table>",
			want: "First cell\nSecond cell",
		},
		{
			name: "links keep their target",
			html: `<p>Read <a href="https://example.com/x">the post</a></p>`,
			want: "Read the post <https://example.com/x>",
		},
		{
			name: "a link that is its own url is not doubled",
			html: `<a href="https://example.com">https://example.com</a>`,
			want: "https://example.com",
		},
		{
			name: "entities decode and indentation collapses",
			html: "<div>\n\t  Tom &amp; Jerry&nbsp;&mdash; 5&nbsp;PM\n</div>",
			want: "Tom & Jerry — 5 PM",
		},
		{
			name: "images speak only with alt text",
			html: `<p><img src="spacer.gif" alt=""><img src="logo.png" alt="Reddit"> Digest</p>`,
			want: "[image: Reddit] Digest",
		},
		{
			name: "lists",
			html: "<ul><li>one</li><li>two</li></ul>",
			want: "one\ntwo",
		},
		{
			name: "pre keeps its whitespace",
			html: "<pre>  a  b\n  c</pre>",
			want: "  a  b\n  c",
		},
		{
			name: "empty document renders to nothing",
			html: "<html><head><style>x{}</style></head><body></body></html>",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := htmlToText(tt.html); got != tt.want {
				t.Errorf("htmlToText:\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

// TestHTMLToTextNoMarkup is the property that matters at the call site: whatever comes out,
// it is not the source. A malformed fragment must still render rather than fall back to
// emitting tags.
func TestHTMLToTextNoMarkup(t *testing.T) {
	got := htmlToText(`<div class="x"><b>bold<i>and italic</b></i><div>next`)
	if strings.ContainsAny(got, "<>") {
		t.Fatalf("rendering still contains markup: %q", got)
	}
	if !strings.Contains(got, "bold") || !strings.Contains(got, "next") {
		t.Fatalf("rendering lost content: %q", got)
	}
}

// TestParseInboundMIME_HTMLOnly is the reported case end to end: a bulk sender's HTML-only
// message must arrive with a readable text/plain body, the HTML preserved as the alternative.
func TestParseInboundMIME_HTMLOnly(t *testing.T) {
	raw := "From: Reddit <noreply@redditmail.com>\r\n" +
		"To: <alice@bridge.test>\r\n" +
		"Subject: Disabled and will be deleted\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><head><style>.b{color:#fff}</style></head><body>" +
		"<table><tr><td><p>Your account will be deleted.</p></td></tr>" +
		`<tr><td><a href="https://reddit.com/keep">Keep it</a></td></tr></table></body></html>` + "\r\n"

	parsed, err := parseInboundMIME([]byte(raw))
	if err != nil {
		t.Fatalf("parseInboundMIME: %v", err)
	}
	if parsed.Body.ContentType != "text/plain" {
		t.Fatalf("body content type = %q, want text/plain", parsed.Body.ContentType)
	}
	body := string(parsed.Body.Content)
	// No tags, no CSS. (Angle brackets alone are not the test: a rendered link keeps its
	// target as "text <https://…>".)
	if strings.Contains(body, "<table") || strings.Contains(body, "<p>") || strings.Contains(body, "color:#fff") {
		t.Fatalf("body still carries markup/CSS: %q", body)
	}
	if !strings.Contains(body, "Your account will be deleted.") ||
		!strings.Contains(body, "Keep it <https://reddit.com/keep>") {
		t.Fatalf("body lost content: %q", body)
	}
	if len(parsed.Alternatives) != 1 || parsed.Alternatives[0].ContentType != "text/html" ||
		!strings.Contains(string(parsed.Alternatives[0].Content), "<table>") {
		t.Fatalf("alternatives = %+v, want the original HTML", parsed.Alternatives)
	}
}
