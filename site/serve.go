package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// serve publishes an already-built site directory over HTTP with the security
// headers GitHub Pages cannot send.
//
// This is the self-hosting path: the bytes are identical to what Pages serves,
// so moving dmcn.dev onto our own machine means pointing DNS at this process
// (behind a TLS terminator) instead of at GitHub. It is also the local preview.
func serve(dir, addr string, dev bool) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("serve %s: %w (run `make site` first)", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("serve %s: not a directory", dir)
	}

	files := http.FileServer(http.Dir(dir))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same policy as the generated _headers, so both hosting paths behave
		// identically. No script-src at all: the site has no JavaScript.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self' 'unsafe-inline'; font-src 'self'; "+
				"img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !dev {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Build-time bookkeeping is not content.
		base := filepath.Base(r.URL.Path)
		if strings.HasPrefix(base, ".") || base == "_headers" {
			http.NotFound(w, r)
			return
		}

		// Serve the styled 404 page rather than net/http's plain text one.
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/")))); err != nil {
			if page, readErr := os.ReadFile(filepath.Join(dir, "404.html")); readErr == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(page)
				return
			}
		}

		files.ServeHTTP(w, r)
	})

	fmt.Printf("site: serving %s on http://localhost%s\n", dir, addr)
	return http.ListenAndServe(addr, handler)
}
