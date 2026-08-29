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
			name: "links are numbered and listed in full at the end",
			html: `<p>Read <a href="https://example.com/x">the post</a></p>`,
			want: "Read [the post][1]\n\n--\n[1]: https://example.com/x\n",
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
	// No tags, no CSS.
	if strings.Contains(body, "<table") || strings.Contains(body, "<p>") || strings.Contains(body, "color:#fff") {
		t.Fatalf("body still carries markup/CSS: %q", body)
	}
	// The prose reads as prose, and the target is recoverable in full from the reference list.
	if !strings.Contains(body, "Your account will be deleted.") ||
		!strings.Contains(body, "[Keep it][1]") ||
		!strings.Contains(body, "[1]: https://reddit.com/keep") {
		t.Fatalf("body lost content: %q", body)
	}
	if len(parsed.Alternatives) != 1 || parsed.Alternatives[0].ContentType != "text/html" ||
		!strings.Contains(string(parsed.Alternatives[0].Content), "<table>") {
		t.Fatalf("alternatives = %+v, want the original HTML", parsed.Alternatives)
	}
}

// A digest in the shape real bulk mail arrives in: every phrase wrapped in a long tracking
// redirect, decorative images, and a preheader padded with invisible characters. The message
// must read as a message, and every link must still be recoverable in full.
func TestHTMLToText_BulkMailStaysReadable(t *testing.T) {
	const track = "https://click.redditmail.com/CL0/https:%2F%2Fwww.reddit.com%2Fr%2FGMail%2F%3F%2524deep_link=true%26correlation_id=90e8aa94-d9f3-479a-97ae-0385c1f1ddf8%26ref=email_digest/1/010001a04b75238b-e5b9fa16-9939-4363-a3a4-9249c54b8364-000000/Rxja1LWyVH2iYguRK3EeglQu_kuxpHhrLcEDHbbm2uM=452"
	const other = track + "&second"
	html := `<div>` +
		`<span>&#847;&zwnj; &#847;&zwnj; &#847;&zwnj; &#847;&zwnj;</span>` +
		`<p><a href="` + track + `">r/GMail</a></p>` +
		`<p>Google suddenly disabled my account</p>` +
		`<p><a href="` + track + `">Read More</a></p>` +
		`<p><a href="` + other + `">Hide r/GMail</a></p>` +
		`<p>5&zwnj;4&zwnj;8 M&zwnj;a&zwnj;rket S&zwnj;t.</p>` +
		`</div>`

	got := htmlToText(html)
	t.Logf("rendering:\n%s", got)

	// The prose is readable: no URL interrupts it.
	body, refs, ok := strings.Cut(got, "\n\n--\n")
	if !ok {
		t.Fatal("no reference list emitted")
	}
	if strings.Contains(body, "http") {
		t.Errorf("a URL leaked into the message text:\n%s", body)
	}
	for _, want := range []string{"[r/GMail][1]", "[Read More][1]", "[Hide r/GMail][2]",
		"Google suddenly disabled my account"} {
		if !strings.Contains(body, want) {
			t.Errorf("message text lost %q:\n%s", want, body)
		}
	}

	// Invisible padding and the zero-width-split address are gone — the address is searchable.
	for _, unwanted := range []string{"\u200c", "\u034f"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("rendering still carries an invisible character %q", unwanted)
		}
	}
	if !strings.Contains(body, "548 Market St.") {
		t.Errorf("zero-width-split address was not reassembled:\n%s", body)
	}

	// Nothing is hidden: every distinct target survives in full, once.
	if !strings.Contains(refs, "[1]: "+track+"\n") {
		t.Errorf("target 1 not listed in full:\n%s", refs)
	}
	if !strings.Contains(refs, "[2]: "+other+"\n") {
		t.Errorf("target 2 not listed in full:\n%s", refs)
	}
	if strings.Count(refs, "[1]:") != 1 {
		t.Errorf("a repeated destination was listed more than once:\n%s", refs)
	}
}

// A message with no links must not grow an empty reference section.
func TestHTMLToText_NoLinksNoReferenceList(t *testing.T) {
	got := htmlToText(`<p>Just a note.</p>`)
	if strings.Contains(got, "--") {
		t.Errorf("emitted a reference list for a message with no links: %q", got)
	}
}
