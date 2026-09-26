package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/mertenvg/logr/v2"
	"github.com/pires/go-proxyproto"

	"dmcn.dev/open-dmcn/internal/registry"
)

// smtpTLS configures transport security for the inbound SMTP listener.
type smtpTLS struct {
	config   *tls.Config // server certificate(s); enables STARTTLS when non-nil
	require  bool        // reject mail until the connection is upgraded to TLS
	implicit bool        // wrap the listener in TLS (SMTPS) instead of STARTTLS
}

// SMTPServer wraps go-smtp to receive inbound legacy email and pass it
// to the InboundHandler.
type SMTPServer struct {
	server      *smtp.Server
	handler     *InboundHandler
	ctx         context.Context
	tls         *smtpTLS
	proxyPolicy proxyproto.ConnPolicyFunc // non-nil ⇒ accept PROXY protocol from trusted proxies
	log         logr.Logger
	mu          sync.Mutex
	started     bool
}

// NewSMTPServer creates a new SMTP server that delivers inbound messages
// to the provided InboundHandler. limits enforces abuse controls (per-IP and
// per-sender rate limits, concurrent-connection cap); if nil, defaults apply.
// tlsOpts configures transport security; if nil, the listener runs in plaintext
// (dev only). When a certificate is configured, STARTTLS is advertised and AUTH
// is refused on unencrypted connections.
func NewSMTPServer(ctx context.Context, addr string, handler *InboundHandler, domain string, limits *inboundLimits, tlsOpts *smtpTLS, proxyPolicy proxyproto.ConnPolicyFunc, log logr.Logger) *SMTPServer {
	if limits == nil {
		limits = newInboundLimits(0, 0, 0)
	}
	if tlsOpts == nil {
		tlsOpts = &smtpTLS{}
	}
	s := &SMTPServer{
		handler:     handler,
		ctx:         ctx,
		tls:         tlsOpts,
		proxyPolicy: proxyPolicy,
		log:         log,
	}

	// require-TLS only makes sense with STARTTLS available; implicit TLS already
	// guarantees every connection is encrypted.
	requireTLS := tlsOpts.require && tlsOpts.config != nil && !tlsOpts.implicit
	be := &smtpBackend{handler: handler, ctx: ctx, limits: limits, requireTLS: requireTLS, log: log}
	srv := smtp.NewServer(be)
	srv.Addr = addr
	srv.Domain = domain
	srv.TLSConfig = tlsOpts.config
	// Allow plaintext AUTH only when no certificate is configured (dev). With TLS
	// available, AUTH must happen over an encrypted channel.
	srv.AllowInsecureAuth = tlsOpts.config == nil
	srv.MaxMessageBytes = 4 * 1024 * 1024
	srv.MaxRecipients = 100

	s.server = srv
	return s
}

// Start begins listening for SMTP connections in a goroutine.
func (s *SMTPServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}

	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}

	s.server.Addr = ln.Addr().String()
	// PROXY protocol: parse the real client address from trusted upstream proxies
	// (load balancers) so SPF + per-IP rate limits see the actual sender, not the
	// proxy. Must wrap BEFORE TLS — the PROXY header precedes the TLS handshake.
	if s.proxyPolicy != nil {
		ln = &proxyproto.Listener{Listener: ln, ConnPolicy: s.proxyPolicy, ReadHeaderTimeout: 10 * time.Second}
	}
	// Implicit TLS (SMTPS): wrap the listener so every connection is encrypted
	// from the first byte, instead of upgrading via STARTTLS.
	if s.tls.implicit && s.tls.config != nil {
		ln = tls.NewListener(ln, s.tls.config)
	}
	s.started = true
	switch {
	case s.tls.implicit && s.tls.config != nil:
		s.log.Infof("SMTP server listening on %s (implicit TLS)", s.server.Addr)
	case s.tls.config != nil:
		s.log.Infof("SMTP server listening on %s (STARTTLS%s)", s.server.Addr, map[bool]string{true: ", required", false: ""}[s.tls.require])
	default:
		s.log.Warnf("SMTP server listening on %s (PLAINTEXT — no TLS configured)", s.server.Addr)
	}

	go func() {
		if err := s.server.Serve(ln); err != nil {
			s.log.Debugf("SMTP server stopped: %v", err)
		}
	}()

	return nil
}

// Addr returns the listen address. Only valid after Start().
func (s *SMTPServer) Addr() string {
	return s.server.Addr
}

// Stop gracefully shuts down the SMTP server.
func (s *SMTPServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return nil
	}
	s.started = false
	s.log.Info("SMTP server stopped")
	return s.server.Close()
}

// smtpBackend implements smtp.Backend.
type smtpBackend struct {
	handler    *InboundHandler
	ctx        context.Context
	limits     *inboundLimits
	requireTLS bool
	log        logr.Logger
}

func (b *smtpBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remoteAddr := c.Conn().RemoteAddr().String()

	// Concurrent-connection cap: reject excess connections with a transient
	// error so well-behaved clients retry later.
	release, ok := b.limits.acquireConn()
	if !ok {
		b.log.Warnf("rejecting SMTP connection from %s: too many concurrent connections", remoteAddr)
		return nil, &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "too many concurrent connections, try again later"}
	}

	return &smtpSession{
		handler:     b.handler,
		ctx:         b.ctx,
		limits:      b.limits,
		conn:        c,
		requireTLS:  b.requireTLS,
		log:         b.log,
		remoteIP:    remoteAddr,
		ipKey:       ipKey(remoteAddr),
		releaseConn: release,
	}, nil
}

// smtpSession implements smtp.Session, collecting MAIL FROM, every RCPT TO,
// and DATA before passing to the InboundHandler.
type smtpSession struct {
	handler     *InboundHandler
	ctx         context.Context
	limits      *inboundLimits
	conn        *smtp.Conn
	requireTLS  bool
	log         logr.Logger
	from        string
	rcpts       []inboundRecipient // every accepted RCPT TO, resolved; a transaction may carry many
	remoteIP    string
	ipKey       string
	releaseConn func()
}

func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	// Require an encrypted channel first when configured, so neither credentials
	// nor message content ever crosses the wire in cleartext.
	if s.requireTLS {
		if _, ok := s.conn.TLSConnectionState(); !ok {
			return &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "must issue a STARTTLS command first"}
		}
	}
	// Enforce per-IP and per-sender rate limits at MAIL FROM, before the client
	// transmits any DATA, so abusive traffic is rejected cheaply.
	if !s.limits.allowMessage(s.ipKey, from) {
		s.log.Warnf("rate-limiting inbound from ip=%s sender=%q", s.ipKey, from)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "rate limit exceeded, try again later"}
	}
	s.from = from
	return nil
}

func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	// RCPT confinement: accept mail only for a recipient on a bridge domain this node serves
	// (cheaper than failing at DATA, and stops the bridge accepting mail for domains it does
	// not bridge).
	if !s.handler.servesBridgeDomain(domainOf(to)) {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "relay not permitted for this recipient domain"}
	}
	// Resolve the recipient now, so an unknown address is refused for itself alone. DATA has
	// one reply for every recipient: an unknown address found there would either fail the whole
	// transaction (and duplicate it for the rest on retry) or be dropped without a bounce.
	r, err := s.handler.resolveRecipient(s.ctx, to)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such recipient"}
		}
		s.log.Warnf("recipient lookup for %s failed: %v", to, err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 3}, Message: "recipient lookup failed, try again later"}
	}
	s.rcpts = append(s.rcpts, r)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return err
	}

	if err := s.handler.handle(
		s.ctx, s.remoteIP, s.from, s.rcpts, buf.Bytes(),
	); err != nil {
		s.log.Warnf("inbound message handling failed: %v", err)
		return err
	}

	return nil
}

func (s *smtpSession) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *smtpSession) Logout() error {
	if s.releaseConn != nil {
		s.releaseConn()
	}
	return nil
}
