package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// TestSPACacheControl locks in the cache policy that keeps a PWA deploy from
// serving a stale app: the shell is never stored, content-hashed assets are
// immutable, and the service worker (+ other static files) always revalidate.
func TestSPACacheControl(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":              {Data: []byte("<!doctype html><html><body>shell</body></html>")},
		"assets/index-abc123.js":  {Data: []byte("console.log(1)")},
		"assets/index-def456.css": {Data: []byte(".a{}")},
		"sw.js":                   {Data: []byte("/* service worker */")},
		"manifest.webmanifest":    {Data: []byte("{}")},
	}
	h := spaHandler(fsys, FrontendConfig{})

	cacheControl := func(path string) string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		return rec.Header().Get("Cache-Control")
	}

	cases := []struct {
		path, want string
	}{
		// The shell — direct, explicit, and SPA-route fallback — must never be stored.
		{"/", "no-store"},
		{"/index.html", "no-store"},
		{"/inbox", "no-store"}, // client-side route → falls back to the shell
		// Content-hashed assets are immutable and cache for a year.
		{"/assets/index-abc123.js", "public, max-age=31536000, immutable"},
		{"/assets/index-def456.css", "public, max-age=31536000, immutable"},
		// The service worker and other unhashed static files must revalidate so a new
		// build is picked up promptly — a stale sw.js pins clients to an old app.
		{"/sw.js", "no-cache"},
		{"/manifest.webmanifest", "no-cache"},
	}
	for _, c := range cases {
		if got := cacheControl(c.path); got != c.want {
			t.Errorf("Cache-Control for %s = %q, want %q", c.path, got, c.want)
		}
	}
}

// TestSPAServesTheBuildsCompressedCopies: a hashed asset the build compressed goes out as the
// copy the browser accepts, still immutable; the shell, rendered per request, never does.
func TestSPAServesTheBuildsCompressedCopies(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":                {Data: []byte("<!doctype html><html><body>shell</body></html>")},
		"assets/index-abc123.js":    {Data: []byte("console.log(1)")},
		"assets/index-abc123.js.br": {Data: []byte("BROTLI")},
		"assets/index-abc123.js.gz": {Data: []byte("GZIP")},
	}
	h := spaHandler(fsys, FrontendConfig{})
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	rec := get("/assets/index-abc123.js")
	if rec.Header().Get("Content-Encoding") != "br" || rec.Body.String() != "BROTLI" {
		t.Errorf("asset: Content-Encoding %q, body %q; want the brotli copy", rec.Header().Get("Content-Encoding"), rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("asset: Cache-Control %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
		t.Errorf("asset: Content-Type %q", got)
	}

	for _, path := range []string{"/", "/inbox"} {
		if rec := get(path); rec.Header().Get("Content-Encoding") != "" {
			t.Errorf("shell %s was sent with Content-Encoding %q", path, rec.Header().Get("Content-Encoding"))
		}
	}
}
