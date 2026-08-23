package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/message"
)

// defaultSMTPPort is the well-known inter-MTA SMTP port.
const defaultSMTPPort = "25"

// SMTPSenderConfig configures the real outbound SMTP deliverer (SMTPSender).
type SMTPSenderConfig struct {
	// HELOName is the EHLO/HELO identity announced to the remote MTA — the bridge's public
	// hostname. Defaults to the OS hostname (or "localhost").
	HELOName string
	// Port is the TCP port dialled on each MX host. Defaults to "25".
	Port string
	// DialTimeout bounds the TCP connect to each MX host. Defaults to 30s.
	DialTimeout time.Duration
	// SessionTimeout bounds the whole SMTP exchange per host (connect→QUIT) when the caller's
	// context carries no (earlier) deadline. Defaults to 5m.
	SessionTimeout time.Duration
	// RequireTLS refuses to deliver to a host that does not offer STARTTLS, and VERIFIES its
	// certificate, instead of falling back to cleartext. Off by default — see the note on
	// certificate verification in deliverTo.
	RequireTLS bool
	// TLSConfig is the base config for STARTTLS (ServerName and verification are set per host).
	// Defaults to MinVersion TLS 1.2.
	TLSConfig *tls.Config
	// DKIM, when set, signs every outbound message (RFC 6376) so receivers can verify the
	// bridge as the originator. Strongly recommended — unsigned mail is widely spam-filtered.
	// It is the default/fallback signer; DKIMByDomain overrides it per bridge (From) domain.
	DKIM *DKIMSigner
	// DKIMByDomain holds per-bridge-domain signers (keyed by the From/d= domain, lowercased),
	// for a multi-tenant bridge serving several domains. The signer is chosen by the rewritten
	// From's domain so DKIM d= aligns with From (DMARC). Falls back to DKIM when absent.
	DKIMByDomain map[string]*DKIMSigner
	// Logger receives per-delivery diagnostics. Defaults to a "bridge-smtp" component logger.
	Logger logr.Logger

	// Test hooks (nil = real implementations).
	LookupMX func(ctx context.Context, domain string) ([]*net.MX, error)
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Now      func() time.Time
}

// SMTPSender is the production SMTPDeliverer: it resolves the recipient domain's MX hosts and
// delivers an RFC 5322 message over SMTP with opportunistic (or required) STARTTLS, trying MX
// hosts in preference order until one accepts. It is the real replacement for
// StubSMTPDeliverer for outbound legacy-email bridging (whitepaper §12).
type SMTPSender struct {
	helo           string
	port           string
	dialTimeout    time.Duration
	sessionTimeout time.Duration
	requireTLS     bool
	tlsConfig      *tls.Config
	dkim           *DKIMSigner
	dkimByDomain   map[string]*DKIMSigner
	log            logr.Logger
	lookupMX       func(ctx context.Context, domain string) ([]*net.MX, error)
	dial           func(ctx context.Context, network, addr string) (net.Conn, error)
	now            func() time.Time
}

// NewSMTPSender builds an SMTPSender from cfg, filling in defaults.
func NewSMTPSender(cfg SMTPSenderConfig) *SMTPSender {
	helo := cfg.HELOName
	if helo == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			helo = h
		} else {
			helo = "localhost"
		}
	}
	s := &SMTPSender{
		helo:           helo,
		port:           cfg.Port,
		dialTimeout:    cfg.DialTimeout,
		sessionTimeout: cfg.SessionTimeout,
		requireTLS:     cfg.RequireTLS,
		tlsConfig:      cfg.TLSConfig,
		dkim:           cfg.DKIM,
		dkimByDomain:   cfg.DKIMByDomain,
		log:            cfg.Logger,
		lookupMX:       cfg.LookupMX,
		dial:           cfg.Dial,
		now:            cfg.Now,
	}
	if s.port == "" {
		s.port = defaultSMTPPort
	}
	if s.dialTimeout <= 0 {
		s.dialTimeout = 30 * time.Second
	}
	if s.sessionTimeout <= 0 {
		s.sessionTimeout = 5 * time.Minute
	}
	if s.tlsConfig == nil {
		// Opportunistic STARTTLS does NOT verify the peer certificate, and that is correct
		// rather than a shortcut — it is what every production MTA does (Postfix's
		// smtp_tls_security_level = may) and what RFC 7435 describes.
		//
		// The reasoning is easy to get backwards. The alternative to UNVERIFIED TLS here is not
		// verified TLS, it is CLEARTEXT: there is no trust anchor for SMTP, a large share of
		// mail servers present self-signed or hostname-mismatched certificates, and an MX
		// hostname learned from unsigned DNS is not an identity worth checking against anyway.
		// Verifying therefore buys no authentication — it just turns "delivered, encrypted,
		// unauthenticated" into "bounced", which is worse on both counts.
		//
		// Real authentication needs a policy saying which certificate to expect: DANE (TLSA
		// records, DNSSEC-signed) or MTA-STS. Neither is implemented; when one is, it belongs
		// here and NOT as a blanket verify.
		//
		// RequireTLS is the opposite posture — the operator has asserted this path must be
		// protected — so verification is on and a failure refuses delivery.
		s.tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !s.requireTLS, //nolint:gosec // opportunistic by design; see above
		}
	}
	if s.log == nil {
		s.log = logr.With(logr.M("component", "bridge-smtp"))
	}
	if s.lookupMX == nil {
		s.lookupMX = net.DefaultResolver.LookupMX
	}
	if s.dial == nil {
		d := &net.Dialer{Timeout: s.dialTimeout}
		s.dial = d.DialContext
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// dkimFor returns the DKIM signer aligned to the From address's domain (so d= matches From for
// DMARC), falling back to the default signer. nil ⇒ the message is sent unsigned.
func (s *SMTPSender) dkimFor(from string) *DKIMSigner {
	if len(s.dkimByDomain) > 0 {
		if sg, ok := s.dkimByDomain[strings.ToLower(domainOf(from))]; ok {
			return sg
		}
	}
	return s.dkim
}

// Deliver resolves the recipient's MX hosts and delivers the message to the first one that
// accepts it (preference order). Returns an error aggregating every host failure if none do.
func (s *SMTPSender) Deliver(ctx context.Context, from, to string, msg *message.PlaintextMessage) error {
	to = strings.TrimSpace(to)
	at := strings.LastIndex(to, "@")
	if at <= 0 || at == len(to)-1 {
		return fmt.Errorf("smtp: recipient %q is not a valid address", to)
	}
	domain := to[at+1:]

	raw, err := buildMIME(from, to, msg, s.now())
	if err != nil {
		return err
	}
	// DKIM-sign with the signer for the From (bridge) domain so d= aligns with From (DMARC).
	if signer := s.dkimFor(from); signer != nil {
		if raw, err = signer.Sign(raw); err != nil {
			return err
		}
	}
	hosts, err := s.mxHosts(ctx, domain)
	if err != nil {
		return fmt.Errorf("smtp: resolve MX for %s: %w", domain, err)
	}

	var errs []error
	for _, h := range hosts {
		if derr := s.deliverTo(ctx, h, from, to, raw); derr != nil {
			s.log.Warnf("delivery to %s via %s failed: %v", to, h, derr)
			errs = append(errs, fmt.Errorf("%s: %w", h, derr))
			continue
		}
		s.log.Infof("delivered to %s via %s", to, h)
		return nil
	}
	return fmt.Errorf("smtp: all %d MX host(s) failed for %s: %w", len(hosts), domain, errors.Join(errs...))
}

// mxHosts returns the recipient domain's MX hosts in preference order. With no MX records it
// falls back to the domain itself (implicit MX, RFC 5321 §5.1); a single null MX ("." host,
// RFC 7505) is an explicit "accepts no mail" and is rejected.
func (s *SMTPSender) mxHosts(ctx context.Context, domain string) ([]string, error) {
	recs, err := s.lookupMX(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return []string{domain}, nil // no MX record set → implicit MX
		}
		return nil, err
	}
	if len(recs) == 1 && strings.TrimSuffix(recs[0].Host, ".") == "" {
		return nil, fmt.Errorf("smtp: %s publishes a null MX (accepts no mail)", domain)
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Pref < recs[j].Pref })
	hosts := make([]string, 0, len(recs))
	for _, r := range recs {
		if h := strings.TrimSuffix(r.Host, "."); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return []string{domain}, nil
	}
	return hosts, nil
}

// deliverTo runs one SMTP session against host: connect, EHLO, opportunistic/required
// STARTTLS, MAIL/RCPT/DATA, QUIT. net/smtp's DATA writer handles CRLF normalisation and
// dot-stuffing, so msg may use bare-LF line endings.
func (s *SMTPSender) deliverTo(ctx context.Context, host, from, to string, msg []byte) error {
	conn, err := s.dial(ctx, "tcp", net.JoinHostPort(host, s.port))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Bound the whole exchange: the sooner of our session budget and any caller deadline.
	// Uses the real clock (not s.now, which is the injectable message-Date source).
	deadline := time.Now().Add(s.sessionTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	if err := c.Hello(s.helo); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		// Only the server name is per-host; the verification policy was decided once, at
		// construction, so a caller that supplied its own TLSConfig keeps it intact.
		tc := s.tlsConfig.Clone()
		tc.ServerName = host
		if err := c.StartTLS(tc); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	} else if s.requireTLS {
		return fmt.Errorf("host does not offer STARTTLS and RequireTLS is set")
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finalise DATA: %w", err)
	}
	return c.Quit()
}
