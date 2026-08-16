package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// siteFS holds the templates and static assets. The design system (tokens,
// base CSS, Geist woff2) is copied from the DMCN marketing sites so the
// protocol's home reads as part of the same family; docs.css is this site's
// own, and there is no site.js — dmcn.dev ships zero JavaScript.
//
//go:embed templates static content
var siteFS embed.FS

// generatedMarker is written into the output directory so a later build can
// tell "this is my output, safe to replace" from "the operator pointed -out at
// the wrong directory". Without it, a stray `-out ~/` would be unrecoverable.
const generatedMarker = ".site-generated"

// layer is one row of the stack table on the home page. It mirrors the layered
// stack at the top of SPEC.md; the spec is the authority, this is the shop
// window.
//
// Detail is template.HTML because these strings carry <code> markup and are
// author-controlled constants in this file — never user input, never content
// read from disk.
type layer struct {
	Name   string
	Detail template.HTML
}

var layers = []layer{
	{"User identity", "An Ed25519 signing key and an X25519 key-exchange key. The address is <code>local@domain</code>, and its record signs itself."},
	{"Resolution", "A <code>_dmcn.&lt;domain&gt;</code> TXT record gives you a fingerprint to trust and a few nodes to dial. You fetch signed records from that domain's own nodes and check them against the fingerprint."},
	{"Message model", "PlaintextMessage → SignedMessage → EncryptedEnvelope. One AES-256-GCM key per message, wrapped to each recipient over X25519. Header and body seal separately, and both get padded to fixed size classes."},
	{"Routing", "RelayHints say which relays hold a mailbox. They sit outside the owner's signature, so an operator can move a mailbox without the owner's key — and the address never changes."},
	{"Relay service", "<code>/dmcn/relay/1.0.0</code> — store, fetch, mailbox operations, record lookups, onion forwarding. Length-prefixed protobuf over libp2p."},
	// Name is a plain string, so html/template escapes it — write literal "&", not "&amp;".
	{"Trust & federation", "Each domain has an authority record, anchored in DNS, that delegates to issuers. Peers swap and verify credentials at <code>/dmcn/join</code> before they federate."},
	{"Transport", "libp2p streams. Discovery is DNS-seeded — no DHT, on purpose."},
}

// pageSpec declares one output page.
type pageSpec struct {
	url    string // clean URL path: "/", "/spec/", or a literal file like "/404.html"
	src    string // markdown filename under content/; empty means the external spec
	tmpl   string // template to execute
	toc    bool   // build and render a table of contents
	vanity bool   // emit the Go go-import/go-source meta tags
	note   string // optional callout above the body ({{repo}}/{{branch}} expanded)
}

// pages is the whole site.
//
// The Go module page and the site root BOTH carry the vanity meta. The go
// command asks for the full import path first (/open-dmcn/dmcnpb?go-get=1),
// then trims path elements and retries, so the module page answers directly and
// the root answers as a fallback if the trim goes all the way up. Serving it in
// both places costs two meta tags and removes a class of "works on my machine".
func sitePages() []pageSpec {
	modulePage := pageSpec{
		url: "/" + moduleName + "/", src: "module.md",
		tmpl: "doc.html", toc: true, vanity: true,
	}
	if !vanityActive {
		modulePage.note = pendingNote
	}
	return []pageSpec{
		{url: "/", src: "index.md", tmpl: "home.html", vanity: true},
		{url: "/spec/", src: "", tmpl: "doc.html", toc: true, note: specNote},
		{url: "/quickstart/", src: "quickstart.md", tmpl: "doc.html", toc: true},
		{url: "/faq/", src: "faq.md", tmpl: "doc.html", toc: true},
		modulePage,
		{url: "/404.html", src: "404.md", tmpl: "page.html"},
	}
}

// specNote sits above the rendered specification. It states the two things a
// reader needs before reading anything else: that this page has no separate
// copy to drift, and that the implementation wins where the two disagree.
const specNote = `<p>This page is rendered directly from <a href="{{repo}}/blob/{{branch}}/SPEC.md"><code>SPEC.md</code></a> in the reference implementation — there is no second copy to drift. It is a <strong>snapshot of the reference implementation, not a frozen specification</strong>: where the two disagree, the implementation and the schemas in <code>proto/</code> are authoritative.</p>`

// pendingNote is shown on the module page while vanityActive is false. Saying
// nothing would be the dishonest option: the meta tags are already served, so
// the path looks live, but `go get` fails until the module declares it too.
const pendingNote = `<p><strong>Not active yet.</strong> This page already serves the <code>go-import</code> meta tag, but the module still declares <code>{{repo-path}}</code> in its <code>go.mod</code>, so <code>go get</code> on the vanity path will fail until the two agree. Use <code>{{repo-path}}</code> until this note disappears.</p>`

// pageData is what every template sees.
type pageData struct {
	Cfg         SiteConfig
	Title       string
	Description string
	Path        string
	Tagline     string
	Body        template.HTML
	Note        template.HTML
	TOC         []tocEntry
	Vanity      *Vanity
	Layers      []layer
}

// build renders the whole site into outDir.
func build(cfg SiteConfig, outDir, specPath string) error {
	outDir = filepath.Clean(outDir)
	if err := prepareOutput(outDir); err != nil {
		return err
	}

	vanity := &Vanity{Module: cfg.ModulePath, Repo: cfg.RepoURL, Branch: cfg.Branch}

	if !vanityActive {
		fmt.Fprintf(os.Stderr,
			"site: WARNING — the vanity import path %s is served but NOT active:\n"+
				"      ../go.mod still declares a different module path, so `go get %s` fails.\n"+
				"      Activate it by changing the module path and setting vanityActive = true.\n",
			cfg.ModulePath, cfg.ModulePath)
	}

	var rendered []string
	for _, p := range sitePages() {
		data, err := renderPage(cfg, p, specPath, vanity)
		if err != nil {
			return fmt.Errorf("%s: %w", p.url, err)
		}
		tmpl, err := template.New("layout.html").Funcs(template.FuncMap{"icon": iconHTML}).
			ParseFS(siteFS, "templates/layout.html", "templates/header.html",
				"templates/footer.html", "templates/"+p.tmpl)
		if err != nil {
			return fmt.Errorf("%s: parse templates: %w", p.url, err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return fmt.Errorf("%s: execute: %w", p.url, err)
		}
		if err := writeFile(outDir, outputPath(p.url), buf.Bytes()); err != nil {
			return err
		}
		if !strings.HasSuffix(p.url, ".html") {
			rendered = append(rendered, p.url)
		}
	}

	if err := copyStatic(outDir); err != nil {
		return err
	}
	return writeExtras(cfg, outDir, rendered)
}

// expand substitutes the deploy constants into authored text — markdown content
// and the note callouts alike.
//
// It exists so that NOTHING outside main.go's constants names the repository.
// A hardcoded `git clone https://github.com/…` in a markdown file would survive
// a repository move and quietly send readers to the wrong place, which is
// exactly the coupling the vanity import path exists to remove.
// TestNoHardcodedRepo enforces it.
func expand(cfg SiteConfig, s string) string {
	return strings.NewReplacer(
		"{{repo}}", cfg.RepoURL,
		"{{repo-path}}", strings.TrimPrefix(cfg.RepoURL, "https://"),
		"{{branch}}", cfg.Branch,
		"{{module}}", cfg.ModulePath,
		"{{module-docs}}", "https://pkg.go.dev/"+cfg.ModulePath,
	).Replace(s)
}

// renderPage assembles the data for one page.
func renderPage(cfg SiteConfig, p pageSpec, specPath string, vanity *Vanity) (*pageData, error) {
	var (
		src []byte
		err error
	)
	if p.src == "" {
		// The specification is read from the repository root, not copied into
		// site/content. There is exactly one SPEC.md and this renders it.
		if src, err = os.ReadFile(specPath); err != nil {
			return nil, fmt.Errorf("read spec: %w", err)
		}
	} else if src, err = siteFS.ReadFile("content/" + p.src); err != nil {
		return nil, err
	}

	doc, err := renderMarkdown([]byte(expand(cfg, string(src))))
	if err != nil {
		return nil, err
	}

	title, desc := doc.Meta["title"], doc.Meta["description"]
	if title == "" {
		title = "Specification"
	}
	if desc == "" {
		desc = firstParagraph(src)
	}

	data := &pageData{
		Cfg:         cfg,
		Title:       title + " · " + cfg.Domain,
		Description: desc,
		Path:        p.url,
		Tagline:     doc.Meta["tagline"],
		Body:        doc.Body,
		Layers:      layers,
	}
	if p.toc {
		data.TOC = doc.TOC
	}
	if p.vanity {
		data.Vanity = vanity
	}
	if p.note != "" {
		data.Note = template.HTML(expand(cfg, p.note))
	}
	return data, nil
}

// outputPath maps a clean URL to a file inside the output directory.
// "/" → index.html, "/spec/" → spec/index.html, "/404.html" → 404.html.
func outputPath(url string) string {
	trimmed := strings.Trim(url, "/")
	if strings.HasSuffix(url, ".html") {
		return trimmed
	}
	if trimmed == "" {
		return "index.html"
	}
	return filepath.Join(trimmed, "index.html")
}

// prepareOutput clears the output directory, refusing to touch a non-empty
// directory that this generator did not produce.
func prepareOutput(outDir string) error {
	entries, err := os.ReadDir(outDir)
	switch {
	case os.IsNotExist(err):
		return os.MkdirAll(outDir, 0o755)
	case err != nil:
		return err
	}
	if len(entries) > 0 {
		if _, err := os.Stat(filepath.Join(outDir, generatedMarker)); err != nil {
			return fmt.Errorf("refusing to overwrite %s: not empty and has no %s marker "+
				"(if this really is the site output directory, create the marker by hand)",
				outDir, generatedMarker)
		}
	}
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	return os.MkdirAll(outDir, 0o755)
}

func writeFile(outDir, rel string, b []byte) error {
	full := filepath.Join(outDir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, b, 0o644)
}

// copyStatic mirrors the embedded static tree into the output.
func copyStatic(outDir string) error {
	return fs.WalkDir(siteFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := siteFS.ReadFile(p)
		if err != nil {
			return err
		}
		return writeFile(outDir, filepath.FromSlash(p), b)
	})
}

// writeExtras emits the files that are configuration rather than content.
func writeExtras(cfg SiteConfig, outDir string, urls []string) error {
	files := map[string]string{
		// The marker that lets the next build safely clear this directory.
		generatedMarker: "Generated by open-dmcn/site. Do not edit by hand; run `make site`.\n",

		// GitHub Pages: the custom domain, and the opt-out from Jekyll (which
		// would otherwise strip files whose names begin with an underscore —
		// _headers among them).
		"CNAME":      cfg.Domain + "\n",
		".nojekyll":  "",
		"robots.txt": "User-agent: *\nAllow: /\n\nSitemap: " + cfg.BaseURL + "/sitemap.xml\n",

		// _headers is the Cloudflare Pages / Netlify convention. GitHub Pages
		// ignores it — it cannot send custom headers at all, which is the one
		// real cost of hosting there. It is written now so that moving dmcn.dev
		// behind a host that DOES honour it (or behind our own terminator, via
		// `site serve`) is a DNS change and nothing more.
		//
		// Stricter than the product sites: this site has no JavaScript, no
		// forms and no outbound connections, so everything is 'none' except the
		// same-origin CSS and fonts. style-src needs 'unsafe-inline' because the
		// design system styles layout with inline style attributes.
		"_headers": "/*\n" +
			"  Content-Security-Policy: default-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\n" +
			"  X-Content-Type-Options: nosniff\n" +
			"  X-Frame-Options: DENY\n" +
			"  Referrer-Policy: no-referrer\n" +
			"  Strict-Transport-Security: max-age=31536000; includeSubDomains\n",
	}

	var sitemap strings.Builder
	sitemap.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sitemap.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, u := range urls {
		sitemap.WriteString("  <url><loc>" + cfg.BaseURL + u + "</loc></url>\n")
	}
	sitemap.WriteString("</urlset>\n")
	files["sitemap.xml"] = sitemap.String()

	for name, body := range files {
		if err := writeFile(outDir, name, []byte(body)); err != nil {
			return err
		}
	}
	return nil
}
