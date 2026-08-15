package main

import (
	"bytes"
	"fmt"
	"html"
	"html/template"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	gmtext "github.com/yuin/goldmark/text"
)

// tocEntry is one top-level (##) section of a rendered document.
type tocEntry struct {
	ID   string
	Text string
}

// document is a parsed markdown source: its front matter, its rendered body and
// the table of contents built from its ## headings.
type document struct {
	Meta map[string]string
	Body template.HTML
	TOC  []tocEntry
}

// md is the shared renderer.
//
// GFM gives us tables (the spec's wire-protocol table needs them) and
// strikethrough/autolinks. WithAutoHeadingID makes every section deep-linkable,
// which is what the spec's TOC links to and what lets someone cite §5 by URL.
//
// WithUnsafe permits raw HTML in markdown. Every source file this renderer ever
// sees is first-party content committed to this repository — the same trust
// level as the templates themselves — and the FAQ needs native <details>
// disclosures. No user-submitted content passes through here.
var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	goldmark.WithRendererOptions(gmhtml.WithUnsafe()),
)

// renderMarkdown parses a markdown source into a document.
func renderMarkdown(src []byte) (*document, error) {
	meta, body := splitFrontMatter(src)

	root := md.Parser().Parse(gmtext.NewReader(body))

	var toc []tocEntry
	err := ast.Walk(root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		h, ok := n.(*ast.Heading)
		if !ok || h.Level != 2 {
			return ast.WalkContinue, nil
		}
		id, ok := h.AttributeString("id")
		if !ok {
			return ast.WalkContinue, nil
		}
		idStr, ok := id.([]byte)
		if !ok {
			return ast.WalkContinue, nil
		}
		toc = append(toc, tocEntry{ID: string(idStr), Text: headingText(h, body)})
		return ast.WalkContinue, nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk headings: %w", err)
	}

	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, body, root); err != nil {
		return nil, fmt.Errorf("render markdown: %w", err)
	}

	return &document{
		Meta: meta,
		Body: template.HTML(postProcess(buf.String())),
		TOC:  toc,
	}, nil
}

// headingText flattens a heading's inline children to plain text for the TOC —
// code spans, emphasis and links all collapse to their text content.
func headingText(n ast.Node, src []byte) string {
	var b strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch t := c.(type) {
		case *ast.Text:
			b.Write(t.Segment.Value(src))
		case *ast.String:
			b.Write(t.Value)
		default:
			b.WriteString(headingText(c, src))
		}
	}
	return strings.TrimSpace(b.String())
}

var headingRe = regexp.MustCompile(`(?s)<h([23]) id="([^"]+)">(.*?)</h[23]>`)

// postProcess adds the two affordances goldmark does not emit:
//
//   - a quiet "#" anchor on every h2/h3, so any section of the spec is citable
//     by URL rather than by screenshot;
//   - a scroll container around every table, so a wide table scrolls itself
//     instead of forcing the whole page sideways on a phone.
func postProcess(s string) string {
	s = headingRe.ReplaceAllString(s,
		`<h$1 id="$2">$3<a class="hash" href="#$2" aria-label="Link to this section">#</a></h$1>`)
	s = strings.ReplaceAll(s, "<table>", `<div class="table-wrap"><table>`)
	s = strings.ReplaceAll(s, "</table>", `</table></div>`)
	return s
}

// splitFrontMatter peels an optional `---` delimited header off the top of a
// markdown file. It is deliberately a line-based key: value reader rather than
// YAML — the site has four keys (title, description, tagline, template) and no
// appetite for a parser dependency to read them.
func splitFrontMatter(src []byte) (map[string]string, []byte) {
	meta := map[string]string{}
	if !bytes.HasPrefix(src, []byte("---\n")) {
		return meta, src
	}
	rest := src[4:]
	end := bytes.Index(rest, []byte("\n---\n"))
	if end < 0 {
		return meta, src
	}
	for _, line := range strings.Split(string(rest[:end]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		meta[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(val), `"`)
	}
	return meta, rest[end+5:]
}

// firstParagraph returns a plain-text lead sentence for a document that carries
// no explicit description in its front matter — used as the <meta description>
// for SPEC.md, which is authored for the repository and has no front matter.
func firstParagraph(body []byte) string {
	for _, block := range strings.Split(string(body), "\n\n") {
		block = strings.TrimSpace(block)
		if block == "" || strings.HasPrefix(block, "#") || strings.HasPrefix(block, "```") {
			continue
		}
		block = strings.Join(strings.Fields(block), " ")
		block = strings.NewReplacer("**", "", "`", "", "*", "").Replace(block)
		if len(block) > 300 {
			if cut := strings.LastIndex(block[:300], " "); cut > 0 {
				block = block[:cut]
			} else {
				block = block[:300]
			}
			block += "…"
		}
		return html.UnescapeString(block)
	}
	return ""
}
