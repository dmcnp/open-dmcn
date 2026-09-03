package webcore_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/webcore"
)

func TestAuthMiddleware_ValidToken(t *testing.T) {
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	token, _ := ss.Create("alice@dmcn.me")

	var gotAddr string
	handler := webcore.AuthMiddleware(ss)(func(w http.ResponseWriter, r *http.Request) {
		gotAddr = webcore.AddressFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotAddr != "alice@dmcn.me" {
		t.Fatalf("expected alice@dmcn.me in context, got %q", gotAddr)
	}
}

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	handler := webcore.AuthMiddleware(ss)(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	handler := webcore.AuthMiddleware(ss)(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer badtoken")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_ExpiredSession(t *testing.T) {
	// Negative TTL backdates the token's exp so it's already expired (no sleep).
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), -time.Hour, "")
	token, _ := ss.Create("alice@dmcn.me")

	handler := webcore.AuthMiddleware(ss)(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestCORSMiddleware_DevMode(t *testing.T) {
	handler := webcore.CORSMiddleware(true, []string{"https://dmcn.me"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Fatalf("expected * origin in dev mode, got %q", origin)
	}
}

func TestCORSMiddleware_ProdMode(t *testing.T) {
	handler := webcore.CORSMiddleware(false, []string{"https://dmcn.me"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "https://dmcn.me" {
		t.Fatalf("expected https://dmcn.me, got %q", origin)
	}
}

func TestCORSMiddleware_MultiOriginEcho(t *testing.T) {
	handler := webcore.CORSMiddleware(false, []string{"https://get.dmcn.email", "https://dmcn.email", "https://dmcnmail.com"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	// An allowed (non-primary) origin is echoed back.
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://dmcnmail.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "https://dmcnmail.com" {
		t.Fatalf("expected allowed origin echoed, got %q", origin)
	}
	if vary := rr.Header().Values("Vary"); len(vary) == 0 || !strings.Contains(strings.Join(vary, ","), "Origin") {
		t.Fatalf("expected Vary: Origin, got %v", vary)
	}

	// A foreign origin falls back to the primary.
	req = httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != "https://get.dmcn.email" {
		t.Fatalf("expected primary origin for foreign Origin header, got %q", origin)
	}
}

func TestCORSMiddleware_Options(t *testing.T) {
	handler := webcore.CORSMiddleware(true, []string{"https://dmcn.me"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for OPTIONS")
	}))

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if methods := rr.Header().Get("Access-Control-Allow-Methods"); methods == "" {
		t.Fatal("expected Allow-Methods header")
	}
}

func TestCSPMiddleware(t *testing.T) {
	handler := webcore.CSPMiddleware(webcore.CSPConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("expected CSP header, got %q", csp)
	}
	// A per-request nonce gates the single inline runtime-config script.
	if !strings.Contains(csp, "script-src 'self' 'nonce-") {
		t.Fatalf("expected nonce in script-src, got %q", csp)
	}
	// Mailbox sync is plain REST now — no WebSocket origin in connect-src.
	if strings.Contains(csp, "wss://") {
		t.Fatalf("did not expect wss in CSP, got %q", csp)
	}
	// Tightened directives + companion hardening headers.
	for _, want := range []string{"object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("expected %q in CSP, got %q", want, csp)
		}
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options nosniff, got %q", got)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options DENY, got %q", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("expected Referrer-Policy no-referrer, got %q", got)
	}
	// HSTS is set in production (devMode=false) but not in dev.
	if got := rr.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatalf("expected HSTS header in production mode")
	}
}

func TestCSPMiddleware_SameOriginOnly(t *testing.T) {
	handler := webcore.CSPMiddleware(webcore.CSPConfig{ExtraConnectSrc: []string{"https://get.dmcn.email/"}})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "stripe.com") {
		t.Fatalf("CSP must stay same-origin: no third-party hosts, got %q", csp)
	}
	if !strings.Contains(csp, "connect-src 'self' https://get.dmcn.email;") {
		t.Fatalf("expected the extra connect-src origin (trailing slash trimmed), got %q", csp)
	}
	if !strings.Contains(csp, "frame-src 'none'") {
		t.Fatalf("expected frame-src 'none', got %q", csp)
	}
}

func TestRateLimitMiddleware_UnderLimit(t *testing.T) {
	limiter := webcore.RateLimitMiddleware(5)
	handler := limiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, rr.Code)
		}
	}
}

func TestRateLimitMiddleware_OverLimit(t *testing.T) {
	limiter := webcore.RateLimitMiddleware(3)
	handler := limiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}

	// 4th request should be rate limited.
	req := httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}

// imgSrcOf returns the img-src directive from a CSP header ("" when absent).
func imgSrcOf(csp string) string {
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "img-src ") {
			return d
		}
	}
	return ""
}

// The remote-image ceiling is opt-in, and has to be: a srcdoc frame inherits this policy
// and can only narrow it, so the mail client cannot show a remote image unless img-src
// here allows one. Everything else — the marketing sites — must keep the tight default,
// since widening it there buys nothing and costs a post-XSS beacon channel.
func TestCSPMiddleware_RemoteImages(t *testing.T) {
	serve := func(cfg webcore.CSPConfig) string {
		rr := httptest.NewRecorder()
		webcore.CSPMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, httptest.NewRequest("GET", "/test", nil))
		return rr.Header().Get("Content-Security-Policy")
	}

	if got := imgSrcOf(serve(webcore.CSPConfig{})); got != "img-src 'self' data:" {
		t.Fatalf("expected no remote images by default, got %q", got)
	}
	if got := imgSrcOf(serve(webcore.CSPConfig{RemoteImages: true})); !strings.Contains(got, " https:") {
		t.Fatalf("expected https: in img-src with RemoteImages, got %q", got)
	}
	// Widening img-src must not drag anything else open. connect-src is the directive
	// that actually governs exfiltration, and it stays same-origin.
	if csp := serve(webcore.CSPConfig{RemoteImages: true}); !strings.Contains(csp, "connect-src 'self';") {
		t.Fatalf("expected connect-src to stay same-origin, got %q", csp)
	}
}
