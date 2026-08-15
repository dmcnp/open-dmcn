package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moduleDecl reads the module path the protocol module actually declares.
func moduleDecl(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatalf("read ../go.mod: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("no module declaration in ../go.mod")
	return ""
}

// TestVanityPath pins the one invariant that keeps the site honest about Go:
// vanityActive must reflect whether the module really declares the vanity path.
//
// Serving a go-import meta tag is not enough on its own. If the module declares
// github.com/… while the site advertises dmcn.dev/…, `go get` fetches the
// repository and then rejects it for declaring a different path — so the site
// would be promising an import that cannot work. This test fails in BOTH
// directions: advertising a path the module has not adopted, and forgetting to
// clear the "not active yet" notice once it has.
func TestVanityPath(t *testing.T) {
	declared := moduleDecl(t)
	advertised := config().ModulePath

	if got := declared == advertised; got != vanityActive {
		if vanityActive {
			t.Fatalf("vanityActive is true but ../go.mod declares %q, not %q.\n"+
				"Set vanityActive = false, or finish the migration.", declared, advertised)
		}
		t.Fatalf("../go.mod already declares %q — set vanityActive = true so the module "+
			"page stops saying the vanity path is inactive.", declared)
	}
}

// TestModuleNameMatchesPath guards against the module page and the import path
// drifting apart: the page must live at exactly the path go asks for.
func TestModuleNameMatchesPath(t *testing.T) {
	cfg := config()
	if want := cfg.Domain + "/" + cfg.ModuleName; cfg.ModulePath != want {
		t.Fatalf("ModulePath = %q, want %q", cfg.ModulePath, want)
	}
	var found bool
	for _, p := range sitePages() {
		if p.url == "/"+cfg.ModuleName+"/" && p.vanity {
			found = true
		}
	}
	if !found {
		t.Fatalf("no vanity-emitting page at /%s/ — `go get %s` would 404",
			cfg.ModuleName, cfg.ModulePath)
	}
}

// buildInto renders the site to a temp dir and returns a reader for its files.
func buildInto(t *testing.T) (string, func(string) string) {
	t.Helper()
	out := t.TempDir()
	if err := build(config(), out, "../SPEC.md"); err != nil {
		t.Fatalf("build: %v", err)
	}
	return out, func(rel string) string {
		b, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
}

func TestBuildEmitsEveryPage(t *testing.T) {
	out, read := buildInto(t)

	for _, f := range []string{
		"index.html", "spec/index.html", "quickstart/index.html", "faq/index.html",
		"open-dmcn/index.html", "404.html",
		"CNAME", ".nojekyll", "_headers", "robots.txt", "sitemap.xml",
		"static/css/tokens.css", "static/css/site.css", "static/css/docs.css",
		"static/fonts/geist-400.woff2",
	} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing output %s: %v", f, err)
		}
	}

	if got := strings.TrimSpace(read("CNAME")); got != config().Domain {
		t.Errorf("CNAME = %q, want %q", got, config().Domain)
	}
}

// TestVanityMetaServed checks the go-import tag is emitted where the go command
// will look for it. The toolchain requests the full import path first and then
// trims path elements, so the module page answers directly and the site root
// answers as the fallback.
func TestVanityMetaServed(t *testing.T) {
	_, read := buildInto(t)
	cfg := config()

	want := `<meta name="go-import" content="` + cfg.ModulePath + ` git ` + cfg.RepoURL + `">`
	for _, page := range []string{"open-dmcn/index.html", "index.html"} {
		if !strings.Contains(read(page), want) {
			t.Errorf("%s does not serve the go-import meta tag:\n  want %s", page, want)
		}
	}

	if !strings.Contains(read("open-dmcn/index.html"), `<meta name="go-source"`) {
		t.Error("module page is missing the go-source meta tag (pkg.go.dev source links)")
	}
}

// TestSpecIsRenderedFromCanonicalFile is the anti-drift guard: the spec page
// must come from SPEC.md itself, never a copy. If someone adds a duplicate
// under content/, this catches it.
func TestSpecIsRenderedFromCanonicalFile(t *testing.T) {
	if _, err := os.Stat("content/spec.md"); err == nil {
		t.Fatal("content/spec.md exists — the spec page must render ../SPEC.md, not a copy")
	}

	_, read := buildInto(t)
	spec := read("spec/index.html")

	// A line that only exists in SPEC.md, proving the render came from there.
	if !strings.Contains(spec, "MX for identity") {
		t.Error("spec page does not appear to contain SPEC.md's content")
	}
	// Section anchors + TOC, so the spec is citable by URL.
	for _, anchor := range []string{`id="1-identity--addressing"`, `id="5-wire-protocols-libp2p"`} {
		if !strings.Contains(spec, anchor) {
			t.Errorf("spec page missing heading anchor %s", anchor)
		}
	}
	if !strings.Contains(spec, `class="toc-list"`) {
		t.Error("spec page has no table of contents")
	}
}

// TestNoThirdPartySubresources pins the property the whole design system exists
// to protect: every byte the browser loads comes from this origin. Fonts are
// self-hosted, icons are inlined SVG, and there is no JavaScript at all — which
// is what lets the CSP say script-src 'none'.
func TestNoThirdPartySubresources(t *testing.T) {
	out, _ := buildInto(t)

	err := filepath.Walk(out, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".html", ".css":
		default:
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(out, path)
		body := string(b)

		for _, bad := range []string{"<script", "src=\"http", "src='http", "@import url(http", "url(http"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains a third-party or script subresource: %q", rel, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestOutputGuard makes sure the generator refuses to clobber a directory that
// is not its own output — `-out` is a flag, and a typo should not be fatal.
func TestOutputGuard(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "precious.txt"), []byte("do not delete"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := build(config(), dir, "../SPEC.md"); err == nil {
		t.Fatal("build overwrote a non-empty directory with no generated marker")
	}
	if _, err := os.Stat(filepath.Join(dir, "precious.txt")); err != nil {
		t.Fatalf("build destroyed an unrelated file: %v", err)
	}
}
