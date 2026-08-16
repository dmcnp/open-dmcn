// Package server provides the HTTP server, routing, and TLS configuration
// for the DMCN web client backend.
package server

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/mertenvg/logr/v2"
	"golang.org/x/crypto/acme/autocert"

	"dmcn.dev/open-dmcn/internal/web/api"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// FrontendConfig holds non-secret, deploy-specific values rendered into the SPA
// shell (index.html) as the global `env` object, so one embedded build can be
// configured per deploy without rebuilding the frontend.
type FrontendConfig struct {
	Version       string
	DefaultDomain string
	// Domains is the comma-separated set of domains the register UI offers in its
	// domain picker (env.DOMAINS). The authoritative registrability check lives on
	// the account service (fleet permits + DAR policy) — this is presentation only.
	Domains        string
	DevMode        bool
	PollIntervalMs int
	// AccountURL is the base URL of the brand's funnel/account service
	// (env.ACCOUNT_URL) — the SPA sends register/countersign/billing calls there.
	// Empty hides those surfaces entirely.
	AccountURL string
	// RegistrationClosed marks a deployment that offers no public signup (the
	// business front door): the register page shows a closed screen and login's
	// "create an account" links point at SignupURL instead.
	RegistrationClosed bool
	// SignupURL is where would-be registrants are sent when RegistrationClosed.
	SignupURL string
}

// Config holds HTTP server configuration.
type Config struct {
	ListenAddr string
	Domain     string
	TLSCert    string
	TLSKey     string
	DevMode    bool
	DataDir    string
	// AccountURL is the funnel/account service origin the SPA calls cross-origin
	// (register, billing, countersign). It is added to the CSP connect-src so the
	// browser permits those calls; empty means no account service is configured.
	AccountURL string
}

// Server wraps the standard library HTTP server with DMCN routing.
type Server struct {
	httpServer *http.Server
	mux        *http.ServeMux
	log        logr.Logger
	devMode    bool
	domain     string
}

// New creates a Server with the given configuration and logger.
func New(cfg Config, logger logr.Logger) *Server {
	mux := http.NewServeMux()
	var origins []string
	if cfg.Domain != "" {
		origins = []string{"https://" + cfg.Domain}
	}
	var extraConnect []string
	if cfg.AccountURL != "" {
		extraConnect = []string{cfg.AccountURL}
	}
	// The reference client is self-contained: no Stripe billing and no cross-origin
	// account service, so the CSP stays strict same-origin (Stripe exception off).
	csp := webcore.CSPMiddleware(webcore.CSPConfig{DevMode: cfg.DevMode, Stripe: false, ExtraConnectSrc: extraConnect})
	handler := csp(webcore.CORSMiddleware(cfg.DevMode, origins)(mux))
	return &Server{
		httpServer: &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: handler,
			// Drop connection-level TLS handshake noise (scanners/bots probing
			// with unconfigured SNI hosts) from the default net/http error log,
			// which otherwise floods stderr with lines like
			//   http: TLS handshake error from <ip>: acme/autocert: host "..." not configured in HostWhitelist
			ErrorLog: log.New(&filteredErrorWriter{w: os.Stderr}, "", log.LstdFlags),
		},
		mux:     mux,
		log:     logger,
		devMode: cfg.DevMode,
		domain:  cfg.Domain,
	}
}

// filteredErrorWriter drops per-connection TLS handshake errors from the
// net/http server's ErrorLog. These are unactionable network noise (port
// scanners, bots probing SNI hosts we don't serve) and otherwise dominate the
// logs. All other server error output passes through unchanged.
type filteredErrorWriter struct {
	w io.Writer
}

func (f *filteredErrorWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("http: TLS handshake error")) {
		return len(p), nil
	}
	return f.w.Write(p)
}

// RegisterAPI wires API handlers and the embedded frontend into the server's
// multiplexer. The authMiddleware function wraps handlers that require an
// authenticated session.
func (s *Server) RegisterAPI(
	auth *api.AuthHandler,
	msg *api.MessageHandler,
	ident *api.IdentityHandler,
	mailbox *api.MailboxHandler,
	reg *api.RegisterHandler,
	authMiddleware func(http.HandlerFunc) http.HandlerFunc,
	frontendFS fs.FS,
	frontendConfig FrontendConfig,
) {
	// NOTE (open-dmcn): device pairing is omitted (product client behavior). Self-service
	// registration is served locally here (the daemon is the operator for its own domain).
	rateLimiter := webcore.RateLimitMiddleware(20)
	s.mux.Handle("POST /api/v1/login", rateLimiter(http.HandlerFunc(auth.HandleLogin)))
	s.mux.Handle("POST /api/v1/login/verify", rateLimiter(http.HandlerFunc(auth.HandleLoginVerify)))
	s.mux.Handle("POST /api/v1/import/challenge", rateLimiter(http.HandlerFunc(auth.HandleImportChallenge)))
	s.mux.Handle("POST /api/v1/import", rateLimiter(http.HandlerFunc(auth.HandleImport)))
	s.mux.Handle("GET /api/v1/relay-hints", rateLimiter(http.HandlerFunc(ident.HandleRelayHints)))
	if reg != nil {
		s.mux.Handle("POST /api/v1/register", rateLimiter(http.HandlerFunc(reg.HandleRegister)))
	}

	// Authenticated endpoints.
	s.mux.HandleFunc("POST /api/v1/logout", authMiddleware(auth.HandleLogout))
	s.mux.HandleFunc("POST /api/v1/messages/send", authMiddleware(msg.HandleSend))
	s.mux.HandleFunc("GET /api/v1/identity/lookup", authMiddleware(ident.HandleLookup))
	// Durable mailbox sync: a two-phase challenge/complete the client polls (the
	// browser signs each per-op relay nonce). Replaces the former /ws transport.
	s.mux.HandleFunc("POST /api/v1/mailbox/challenge", authMiddleware(mailbox.HandleChallenge))
	s.mux.HandleFunc("POST /api/v1/mailbox/complete", authMiddleware(mailbox.HandleComplete))

	// Embedded frontend — serve real static files; fall back to index.html for
	// any other path so the SPA's client-side router (BrowserRouter) handles deep
	// links like /inbox or /settings on a full page load.
	if frontendFS != nil {
		s.mux.Handle("/", spaHandler(frontendFS, frontendConfig))
	}
}

// indexData is the html/template payload rendered into the SPA shell. Nonce is
// per request; the rest is deploy config exposed to the app as the global `env`.
type indexData struct {
	Nonce              string
	Version            string
	DefaultDomain      string
	Domains            string
	DevMode            string
	PollIntervalMs     int
	AccountURL         string
	RegistrationClosed string
	SignupURL          string
}

// spaHandler serves the embedded SPA: it returns the requested file when one
// exists, and otherwise renders index.html (HTTP 200) so the in-browser router can
// resolve the route. index.html is an html/template — it carries the per-request
// CSP nonce and the runtime `env` config (so one embedded build is configurable
// per deploy without rebuilding the frontend).
//
// Requests under /api never fall back to the shell — a missing API route must
// 404, not return HTML. (API paths are normally matched by more specific mux
// patterns; this is a guard for unmatched subpaths.)
func spaHandler(fsys fs.FS, cfg FrontendConfig) http.HandlerFunc {
	fileServer := http.FileServerFS(fsys)
	var tpl *template.Template
	if raw, err := fs.ReadFile(fsys, "index.html"); err == nil {
		tpl, _ = template.New("index.html").Parse(string(raw))
	}
	devMode := ""
	if cfg.DevMode {
		devMode = "true"
	}
	registrationClosed := ""
	if cfg.RegistrationClosed {
		registrationClosed = "true"
	}
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		if tpl == nil {
			http.NotFound(w, r)
			return
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, indexData{
			Nonce:              webcore.NonceFromContext(r.Context()),
			Version:            cfg.Version,
			DefaultDomain:      cfg.DefaultDomain,
			Domains:            cfg.Domains,
			DevMode:            devMode,
			PollIntervalMs:     cfg.PollIntervalMs,
			AccountURL:         cfg.AccountURL,
			RegistrationClosed: registrationClosed,
			SignupURL:          cfg.SignupURL,
		}); err != nil {
			http.Error(w, "failed to render index", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The shell must never be stored: it carries a per-request CSP nonce (so it is
		// never reusable) and points at the current content-hashed assets, so any cached
		// copy means clients load a stale app after a deploy. no-store is stronger than
		// no-cache (the browser keeps no copy at all); the service worker is network-first,
		// so it still fetches the fresh shell when online and its own Cache Storage backs
		// offline. The hashed assets the shell references cache freely (see below).
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = buf.WriteTo(w)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "index.html" {
			// Serve only real, non-directory files; everything else gets the shell
			// (this also avoids exposing embedded directory listings, and routes the
			// raw index.html through the template instead of the file server).
			if info, err := fs.Stat(fsys, p); err == nil && !info.IsDir() {
				setStaticCacheControl(w, p)
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, r)
	}
}

// setStaticCacheControl sets Cache-Control for embedded static files served by the
// SPA handler. Vite emits content-hashed files under /assets/, so those are
// immutable and cache for a year — a content change yields a new filename, so a
// stale copy can never be wrong. Everything else (the service worker, the web
// manifest, icons) is served no-cache so a new build is picked up promptly; the
// service worker in particular must never go stale, or it pins clients to an old
// shell-cache lifecycle.
func setStaticCacheControl(w http.ResponseWriter, p string) {
	if strings.HasPrefix(p, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
}

// Start begins listening. If certFile and keyFile are non-empty it starts
// a TLS server; otherwise it starts a plain HTTP server.
func (s *Server) Start(certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		s.log.Info("starting HTTPS server", logr.M("addr", s.httpServer.Addr))
		return s.httpServer.ListenAndServeTLS(certFile, keyFile)
	}
	s.log.Info("starting HTTP server", logr.M("addr", s.httpServer.Addr))
	return s.httpServer.ListenAndServe()
}

// StartAutocert begins listening with automatic TLS certificates from
// Let's Encrypt via the ACME protocol.
func (s *Server) StartAutocert(domain, cacheDir string) error {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
	}
	s.httpServer.TLSConfig = m.TLSConfig()
	s.log.Info("starting HTTPS server with autocert", logr.M("addr", s.httpServer.Addr), logr.M("domain", domain))
	return s.httpServer.ListenAndServeTLS("", "")
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
