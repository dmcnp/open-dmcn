package webcore

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestPickEncoding(t *testing.T) {
	cases := []struct {
		accept string
		want   string
	}{
		{"", ""},
		{"gzip, deflate, br, zstd", "br"}, // what current browsers send
		{"gzip", "gzip"},
		{"GZIP", "gzip"},
		{"br;q=0, gzip", "gzip"},
		{"br;q=0.1, gzip;q=1", "br"}, // a lower q still accepts; this server prefers the smaller copy
		{"br; q=0 , gzip; q=0", ""},
		{"identity", ""},
		{"*", "br"},
		{"*;q=0", ""},
		{"*, br;q=0", "gzip"},
		{"deflate", ""},
		{"br;q=nonsense, gzip", "gzip"}, // an unreadable q is not an acceptance
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.accept != "" {
			r.Header.Set("Accept-Encoding", c.accept)
		}
		if got := PickEncoding(r, Encodings...); got != c.want {
			t.Errorf("Accept-Encoding %q: got %q, want %q", c.accept, got, c.want)
		}
	}
	// Only what is on offer can be picked.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "br")
	if got := PickEncoding(r, "gzip"); got != "" {
		t.Errorf("br-only request, gzip on offer: got %q, want plain", got)
	}
}

func TestServeFileAnswersWithTheCopyTheRequestAccepts(t *testing.T) {
	fsys := fstest.MapFS{
		"assets/app.js":    {Data: []byte("console.log('plain')")},
		"assets/app.js.br": {Data: []byte("BROTLI")},
		"assets/app.js.gz": {Data: []byte("GZIP")},
		"sw.js":            {Data: []byte("/* no copies */")},
	}
	get := func(name, accept string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/"+name, nil)
		if accept != "" {
			r.Header.Set("Accept-Encoding", accept)
		}
		w := httptest.NewRecorder()
		ServeFile(w, r, fsys, name)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s (%q) = %d", name, accept, w.Code)
		}
		return w
	}

	cases := []struct {
		name, accept, encoding, body string
	}{
		{"assets/app.js", "gzip, deflate, br", "br", "BROTLI"},
		{"assets/app.js", "gzip", "gzip", "GZIP"},
		{"assets/app.js", "", "", "console.log('plain')"},
	}
	for _, c := range cases {
		w := get(c.name, c.accept)
		if got := w.Header().Get("Content-Encoding"); got != c.encoding {
			t.Errorf("%s (%q): Content-Encoding %q, want %q", c.name, c.accept, got, c.encoding)
		}
		if got := w.Body.String(); got != c.body {
			t.Errorf("%s (%q): body %q, want %q", c.name, c.accept, got, c.body)
		}
		// The type is the script's, never the compressed copy's.
		if got := w.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
			t.Errorf("%s (%q): Content-Type %q", c.name, c.accept, got)
		}
		// Every answer for a file with copies varies by Accept-Encoding, the plain one included:
		// a cache that kept the plain answer must not give it to a browser that takes brotli,
		// nor the brotli one to a client that cannot read it.
		if got := w.Header().Get("Vary"); got != "Accept-Encoding" {
			t.Errorf("%s (%q): Vary %q, want Accept-Encoding", c.name, c.accept, got)
		}
	}

	// A file the build did not compress is served as it is, and does not claim to vary.
	w := get("sw.js", "br, gzip")
	if w.Header().Get("Content-Encoding") != "" || w.Header().Get("Vary") != "" || w.Body.String() != "/* no copies */" {
		t.Errorf("sw.js: got encoding %q, vary %q, body %q", w.Header().Get("Content-Encoding"), w.Header().Get("Vary"), w.Body.String())
	}
}
