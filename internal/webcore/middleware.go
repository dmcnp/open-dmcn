package webcore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthMiddleware returns a middleware that validates the Bearer token from
// the Authorization header against the session store and injects the
// associated address into the request context.
func AuthMiddleware(sessions *SessionStore) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == "" || token == authHeader {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			address, err := sessions.Validate(token)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired session"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyAddress, address)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}

// CORSMiddleware returns a middleware that sets CORS headers. In dev mode all
// origins are allowed; in production the request Origin is echoed back when it
// is in allowedOrigins (each an "https://host" origin), otherwise the first
// entry is served as the default. Vary: Origin is set in production because the
// response header depends on the request.
func CORSMiddleware(devMode bool, allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	primary := "*"
	for i, o := range allowedOrigins {
		o = strings.TrimRight(strings.ToLower(strings.TrimSpace(o)), "/")
		if o == "" {
			continue
		}
		if primary == "*" && i == 0 {
			primary = o
		}
		allowed[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := "*"
			if !devMode && primary != "*" {
				origin = primary
				if _, ok := allowed[strings.ToLower(r.Header.Get("Origin"))]; ok {
					origin = strings.ToLower(r.Header.Get("Origin"))
				}
				w.Header().Add("Vary", "Origin")
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// nonceCtxKey keys the per-request CSP nonce in the request context.
type nonceCtxKey struct{}

// NonceFromContext returns the per-request CSP nonce set by CSPMiddleware, or ""
// if none is present. The SPA handler renders it into index.html so the inline
// runtime-config script can execute under the strict, no-unsafe-inline script CSP.
func NonceFromContext(ctx context.Context) string {
	n, _ := ctx.Value(nonceCtxKey{}).(string)
	return n
}

// generateNonce returns a fresh base64 CSP nonce.
func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// CSPConfig tunes the Content-Security-Policy emitted by CSPMiddleware.
type CSPConfig struct {
	// DevMode skips HSTS (avoid pinning localhost).
	DevMode bool
	// ExtraConnectSrc are additional origins allowed in connect-src.
	ExtraConnectSrc []string
}

// CSPMiddleware returns a middleware that sets Content-Security-Policy and the
// companion security headers. It mints a per-request nonce, allows exactly that
// nonce in script-src (so the single inline runtime-config script runs while
// everything else stays no-unsafe-inline / no-eval), and stashes the nonce in the
// request context for the page handler to render.
//
// Key custody is non-extractable + client-only (no server-held key blob), so XSS
// can't *exfiltrate* keys — but it could still drive sign/deriveBits while the page
// is open. These headers shrink that window: a tight CSP plus framing/sniffing/
// referrer hardening (and HSTS in production).
func CSPMiddleware(cfg CSPConfig) func(http.Handler) http.Handler {
	// Scripts: same-origin bundles via 'self' + the one inline config script via
	// its nonce. No 'unsafe-inline'/'unsafe-eval' — the frontend is eval-free
	// (Argon2id runs as pure JS, no WebAssembly, so no wasm-unsafe-eval needed).
	// Inline styles stay allowed: the app uses style= attributes and injects
	// <style> tags, a much lower risk than script execution. object/base-uri/
	// frame-ancestors/form-action are locked down to blunt injection + clickjacking.
	//
	// The reference daemon is entirely self-hosted, so every fetch directive stays
	// same-origin. There is no third-party payment or account service to carve out.
	scriptExtra, frameSrc, connectExtra, imgExtra := "", "'none'", "", ""
	for _, o := range cfg.ExtraConnectSrc {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			connectExtra += " " + o
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := generateNonce()
			csp := fmt.Sprintf(
				"default-src 'self'; script-src 'self' 'nonce-%s'"+scriptExtra+"; style-src 'self' 'unsafe-inline'; "+
					"connect-src 'self'"+connectExtra+"; img-src 'self' data:"+imgExtra+"; font-src 'self'; "+
					"frame-src "+frameSrc+"; "+
					"object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
				nonce,
			)
			w.Header().Set("Content-Security-Policy", csp)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
			// HSTS only over real TLS (production); skip in dev to avoid pinning localhost.
			if !cfg.DevMode {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			ctx := context.WithValue(r.Context(), nonceCtxKey{}, nonce)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// rateLimitEntry tracks request timestamps for a single IP.
type rateLimitEntry struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// RateLimitMiddleware returns a middleware that limits requests per IP
// address to the specified number per minute using a sliding window.
func RateLimitMiddleware(requestsPerMinute int) func(http.Handler) http.Handler {
	var clients sync.Map // IP string → *rateLimitEntry

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			val, _ := clients.LoadOrStore(ip, &rateLimitEntry{})
			entry := val.(*rateLimitEntry)

			now := time.Now()
			windowStart := now.Add(-time.Minute)

			entry.mu.Lock()

			// Prune timestamps outside the sliding window.
			valid := entry.timestamps[:0]
			for _, ts := range entry.timestamps {
				if ts.After(windowStart) {
					valid = append(valid, ts)
				}
			}
			entry.timestamps = valid

			if len(entry.timestamps) >= requestsPerMinute {
				entry.mu.Unlock()
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			entry.timestamps = append(entry.timestamps, now)
			entry.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}
