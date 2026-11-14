package webcore

import (
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Compressed responses for static files.
//
// Nothing here compresses on the fly. A file's compressed copies are made ahead of time by the
// frontend build (name.br and name.gz beside name, see cmd/dmcnd/web/vite.config.ts), and a
// request is answered with the best copy it accepts. That costs no CPU per request and lets the
// build use the slowest, smallest settings.
//
// It is for static files only. A response that mixes a secret with anything a requester can
// influence must not be compressed (the BREACH class of attacks reads the secret out of the
// compressed length), and API responses are mostly ciphertext that would not shrink anyway.

// Encodings is the order compressed copies are preferred in: brotli is smaller, gzip is the
// fallback every client has.
var Encodings = []string{"br", "gzip"}

// encodingSuffix is the file a build writes each encoding's copy to, beside the original.
var encodingSuffix = map[string]string{"br": ".br", "gzip": ".gz"}

// PickEncoding returns the first of available (best first) that r's Accept-Encoding accepts, or ""
// when the plain file is the answer. A coding is accepted when it is listed with a q above zero,
// or covered by "*" without being refused by name.
func PickEncoding(r *http.Request, available ...string) string {
	accepted := map[string]bool{}
	wildcard := false
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		ok := true
		for _, p := range strings.Split(params, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(strings.TrimSpace(k), "q") {
				q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
				ok = err == nil && q > 0
			}
		}
		if name == "*" {
			wildcard = ok
			continue
		}
		accepted[name] = ok
	}
	for _, enc := range available {
		if ok, listed := accepted[enc]; listed {
			if ok {
				return enc
			}
			continue
		}
		if wildcard {
			return enc
		}
	}
	return ""
}

// ServeEncoded answers r with body, which is name's content already encoded as enc. Content-Type
// comes from name, not from the compressed copy, and ranges and conditional requests apply to the
// encoded bytes, as HTTP specifies for a content coding.
func ServeEncoded(w http.ResponseWriter, r *http.Request, name, enc string, body io.ReadSeeker) {
	w.Header().Set("Content-Encoding", enc)
	http.ServeContent(w, r, name, time.Time{}, body)
}

// ServeFile serves name from fsys, answering with a compressed copy (name.br, name.gz) when fsys
// has one the request accepts, and with the file itself otherwise.
func ServeFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	var available []string
	for _, enc := range Encodings {
		if info, err := fs.Stat(fsys, name+encodingSuffix[enc]); err == nil && !info.IsDir() {
			available = append(available, enc)
		}
	}
	if len(available) > 0 {
		// Whatever this request gets, another with a different Accept-Encoding may get something
		// else, and a shared cache must not hand one the other's.
		w.Header().Add("Vary", "Accept-Encoding")
	}
	if enc := PickEncoding(r, available...); enc != "" {
		if f, err := fsys.Open(name + encodingSuffix[enc]); err == nil {
			defer f.Close()
			if rs, ok := f.(io.ReadSeeker); ok {
				ServeEncoded(w, r, name, enc, rs)
				return
			}
		}
	}
	http.ServeFileFS(w, r, fsys, name)
}
