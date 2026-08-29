package bridge

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// htmlToText renders an HTML mail body down to a readable text/plain rendering.
//
// It exists because a great deal of legacy mail — most bulk and transactional mail —
// ships text/html with NO text/plain alternative. DMCN's model is the multipart/alternative
// one: MessageContent.body is the plain rendering every client can read, and the HTML rides
// in Alternatives. Without a rendering here the bridge had to put the HTML source in `body`,
// so a text-only client (and, in the mail client, the trust-gated plain-text peek shown before
// an unknown sender is trusted — exactly the case where the HTML must NOT be rendered) got a
// screenful of markup instead of the message.
//
// This is a rendering, not a tag strip: block elements and table cells become line breaks
// (layout tables are how mail is built), links keep their target, and script/style/head
// content is dropped rather than spilled as text.
func htmlToText(src string) string {
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		// html.Parse only errors on a read failure, not on malformed markup, but never
		// fall back to emitting the source: that is the behavior this function replaces.
		return ""
	}
	w := textWriter{links: &linkTable{}}
	w.render(doc, false)
	return w.String() + w.links.render()
}

// skipContent are elements whose text content is not message content — dropping the
// element alone would spill CSS or script source into the rendering.
var skipContent = map[atom.Atom]bool{
	atom.Head: true, atom.Script: true, atom.Style: true, atom.Title: true,
	atom.Noscript: true, atom.Template: true, atom.Iframe: true, atom.Object: true,
	atom.Embed: true,
}

// lineElem are elements that start and end a line. Table rows and cells are included
// because HTML mail is overwhelmingly laid out in tables — without them a newsletter
// renders as one unbroken paragraph.
var lineElem = map[atom.Atom]bool{
	atom.Div: true, atom.Li: true, atom.Ul: true, atom.Ol: true, atom.Table: true,
	atom.Tr: true, atom.Td: true, atom.Th: true, atom.Section: true, atom.Article: true,
	atom.Header: true, atom.Footer: true, atom.Center: true, atom.Address: true,
	atom.Dt: true, atom.Dd: true, atom.Dl: true, atom.Tbody: true, atom.Thead: true,
	atom.Tfoot: true, atom.Form: true, atom.Nav: true, atom.Main: true, atom.Aside: true,
}

// paraElem are elements separated by a BLANK line — the ones a reader perceives as
// distinct blocks of prose rather than layout scaffolding.
var paraElem = map[atom.Atom]bool{
	atom.P: true, atom.Blockquote: true, atom.H1: true, atom.H2: true, atom.H3: true,
	atom.H4: true, atom.H5: true, atom.H6: true, atom.Pre: true,
}

// linkTable collects the targets of the links in a message so they can be listed once, in
// full, at the end — the numbered-reference form text browsers have used for decades.
//
// Inline targets were the obvious rendering and the wrong one. Bulk mail wraps every phrase
// in a tracking redirect hundreds of characters long, so a digest arrived as far more URL
// than message and the actual words were unreadable between them. Shortening each to its host
// fixed the reading and broke the using: a link is often the POINT of the mail — a sign-in, a
// confirmation, a password reset — and this rendering is what a reader sees when they have
// chosen NOT to trust the sender enough to render its HTML. That is exactly when the link
// still has to work.
//
// So: nothing is dropped and nothing is abbreviated. The text reads as text, and every target
// is recoverable in full, on its own line, ready to copy. Repeats share a number, because one
// destination referenced five times is one destination.
type linkTable struct {
	order []string
	index map[string]int
}

// ref returns the reference number for a target, assigning one on first sight.
func (t *linkTable) ref(href string) int {
	if t.index == nil {
		t.index = map[string]int{}
	}
	if n, ok := t.index[href]; ok {
		return n
	}
	n := len(t.order) + 1
	t.index[href] = n
	t.order = append(t.order, href)
	return n
}

// render writes the reference list, or nothing at all when the message had no links.
//
// The form is markdown's reference-link definition rather than a plain numbered list, because
// it costs nothing and degrades in both directions: read as text it is a legible list of
// targets, and read as markdown it resolves the [text][n] markers above into real links and
// drops these lines entirely. The alternative shape, [text](#n), looks similar but points at
// an in-page anchor that does not exist — a dead link wherever anything actually renders it.
func (t *linkTable) render() string {
	if len(t.order) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n--\n")
	for i, href := range t.order {
		fmt.Fprintf(&b, "[%d]: %s\n", i+1, href)
	}
	return b.String()
}

// textWriter accumulates the rendering. Line breaks are REQUESTED rather than written, so
// nested block boundaries (a <td> inside a <tr> inside a <table>, all closing at once)
// collapse into one break instead of a run of blank lines.
type textWriter struct {
	// links is the document-wide reference table, shared with every nested writer.
	links   *linkTable
	b       strings.Builder
	pending int  // line breaks owed before the next text: 1 = new line, 2 = blank line
	space   bool // a collapsed whitespace run is owed before the next text
}

// line requests a line break; para requests a blank line. Neither emits anything until
// there is more text to separate, so trailing structure never leaves dangling newlines.
func (w *textWriter) line() { w.want(1) }
func (w *textWriter) para() { w.want(2) }

func (w *textWriter) want(n int) {
	if w.b.Len() == 0 {
		return // nothing to separate from yet
	}
	if n > w.pending {
		w.pending = n
	}
	w.space = false // a line break subsumes a pending space
}

// text appends rendered text, first paying out any owed breaks/space.
func (w *textWriter) text(s string) {
	if s == "" {
		return
	}
	if w.pending > 0 {
		w.b.WriteString(strings.Repeat("\n", w.pending))
		w.pending, w.space = 0, false
	}
	if w.space {
		if w.b.Len() > 0 {
			w.b.WriteByte(' ')
		}
		w.space = false
	}
	w.b.WriteString(s)
}

// stripInvisible removes characters that occupy no visual space. They are not content, and in
// mail they are almost always working against the reader: senders pad a preheader with runs of
// them so the inbox preview shows only the line they chose, and split words with them
// ("5<ZWNJ>4<ZWNJ>8 Market St.") to defeat scrapers — which also defeats search, copy-paste and
// a screen reader. A rendering meant to be READ should carry what is visible and nothing else.
//
// Soft hyphen is included: it renders as nothing except at a line break this rendering does not
// perform. Ordinary whitespace is left alone — that is handled by the writer's spacing rules.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\u00ad', // soft hyphen
			r == '\u034f',                  // combining grapheme joiner
			r == '\u061c',                  // arabic letter mark
			r == '\ufeff',                  // zero-width no-break space (BOM)
			r >= '\u200b' && r <= '\u200f', // zero-width space/joiners, LRM/RLM
			r >= '\u2060' && r <= '\u2064', // word joiner, invisible operators
			r >= '\u202a' && r <= '\u202e', // bidi embedding/override
			r >= '\u2066' && r <= '\u2069': // bidi isolates
			return -1
		}
		return r
	}, s)
}

// raw appends text verbatim (inside <pre>, where whitespace is significant).
func (w *textWriter) raw(s string) {
	if s == "" {
		return
	}
	if w.pending > 0 {
		w.b.WriteString(strings.Repeat("\n", w.pending))
		w.pending, w.space = 0, false
	}
	w.b.WriteString(s)
}

func (w *textWriter) String() string { return w.b.String() }

// writeCollapsed appends a text node's content with HTML whitespace rules applied: runs of
// whitespace collapse to a single space, and a space at a boundary is only emitted when real
// text follows it — so the source's own indentation never reaches the rendering.
func (w *textWriter) writeCollapsed(s string) {
	// Before collapsing, not after: a preheader padded with invisible characters is otherwise
	// a run of real runes separated by spaces, so it survives as a blank line at the top of
	// every newsletter. Stripped first, it is just whitespace and the rules below drop it.
	s = stripInvisible(s)
	var b strings.Builder
	space, lead := false, false
	for _, r := range s {
		if isHTMLSpace(r) {
			space = true
			continue
		}
		if space {
			if b.Len() == 0 {
				lead = true
			} else {
				b.WriteByte(' ')
			}
			space = false
		}
		b.WriteRune(r)
	}
	str := b.String()
	if str == "" {
		// A whitespace-only node (the newline between two inline tags): owe a space.
		if s != "" {
			w.space = true
		}
		return
	}
	if lead {
		w.space = true
	}
	w.text(str)
	if space { // trailing whitespace, owed to whatever comes next
		w.space = true
	}
}

// isHTMLSpace reports whether r is whitespace for collapsing purposes. U+00A0 (&nbsp;) is
// included: mail uses it as a layout spacer, and a text rendering wants a plain space.
func isHTMLSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '\v', '\u00a0':
		return true
	}
	return false
}

func (w *textWriter) render(n *html.Node, pre bool) {
	switch n.Type {
	case html.TextNode:
		if pre {
			w.raw(n.Data)
			return
		}
		w.writeCollapsed(n.Data)
		return
	case html.ElementNode:
		if skipContent[n.DataAtom] {
			return
		}
		switch n.DataAtom {
		case atom.Br:
			w.line()
			return
		case atom.Hr:
			w.para()
			w.text("---")
			w.para()
			return
		case atom.Img:
			// Only images that carry alt text say anything; HTML mail is full of
			// spacer and tracking pixels whose placeholders would be pure noise.
			if alt := strings.TrimSpace(attrOf(n, "alt")); alt != "" {
				w.text("[image: " + alt + "]")
			}
			return
		case atom.A:
			w.renderLink(n, pre)
			return
		case atom.Pre:
			w.para()
			w.renderChildren(n, true)
			w.para()
			return
		}
		switch {
		case paraElem[n.DataAtom]:
			w.para()
			w.renderChildren(n, pre)
			w.para()
			return
		case lineElem[n.DataAtom]:
			w.line()
			w.renderChildren(n, pre)
			w.line()
			return
		}
	case html.DocumentNode:
	default:
		// Comments, doctypes: nothing to render.
		return
	}
	w.renderChildren(n, pre)
}

func (w *textWriter) renderChildren(n *html.Node, pre bool) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		w.render(c, pre)
	}
}

// renderLink writes an anchor as "[text][n]", with n indexing the reference list at the end of
// the message (see linkTable). A bare URL used as its own link text, an in-page anchor, or a
// cid: reference is already self-describing and stays as it is.
//
// The brackets around the text are not decoration: they mark where the link began and ended,
// which is the job the old inline "<href>" form did by delimiting the target instead. Link
// text that already carries its own brackets — an image rendered as "[image: alt]" — is not
// bracketed twice; it reads as the link label it already is.
func (w *textWriter) renderLink(n *html.Node, pre bool) {
	inner := textWriter{links: w.links}
	inner.renderChildren(n, pre)
	text := strings.TrimSpace(inner.String())
	href := strings.TrimSpace(attrOf(n, "href"))
	if href == "" || href == text || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "cid:") {
		w.text(text)
		return
	}
	ref := w.links.ref(href)
	if text == "" {
		// An empty anchor still went somewhere; the reference is all there is to show.
		w.text(fmt.Sprintf("[%d]", ref))
		return
	}
	if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
		w.text(fmt.Sprintf("%s[%d]", text, ref))
		return
	}
	w.text(fmt.Sprintf("[%s][%d]", text, ref))
}

func attrOf(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
