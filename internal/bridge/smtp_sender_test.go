package bridge

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"dmcn.dev/open-dmcn/internal/core/message"
)

// plainMsg builds a minimal text/plain DMCN message for SMTPSender.Deliver tests.
func plainMsg(subject, body string) *message.PlaintextMessage {
	return &message.PlaintextMessage{
		Subject: subject,
		Body:    message.MessageBody{ContentType: "text/plain", Content: []byte(body)},
	}
}

// --- a minimal recording go-smtp server for delivery assertions ---

type recordedMsg struct {
	from string
	rcpt []string
	data string
}

type recordingBackend struct {
	mu   sync.Mutex
	msgs []recordedMsg
}

func (b *recordingBackend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &recordingSession{be: b}, nil
}
func (b *recordingBackend) recorded() []recordedMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]recordedMsg(nil), b.msgs...)
}

type recordingSession struct {
	be  *recordingBackend
	cur recordedMsg
}

func (s *recordingSession) Mail(from string, _ *smtp.MailOptions) error {
	s.cur.from = from
	return nil
}
func (s *recordingSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.cur.rcpt = append(s.cur.rcpt, to)
	return nil
}
func (s *recordingSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.cur.data = string(b)
	s.be.mu.Lock()
	s.be.msgs = append(s.be.msgs, s.cur)
	s.be.mu.Unlock()
	return nil
}
func (s *recordingSession) Reset()        { s.cur = recordedMsg{} }
func (s *recordingSession) Logout() error { return nil }

// startRecordingServer starts an in-process go-smtp server on a random port. A non-nil
// tlsConfig makes it advertise STARTTLS.
func startRecordingServer(t *testing.T, tlsConfig *tls.Config) (addr string, be *recordingBackend) {
	t.Helper()
	be = &recordingBackend{}
	srv := smtp.NewServer(be)
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true
	srv.TLSConfig = tlsConfig
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), be
}

// senderTo builds an SMTPSender whose MX resolution always returns "localhost" and whose
// dialer always connects to serverAddr (so tests need no real DNS or port 25).
func senderTo(serverAddr string, cfg SMTPSenderConfig) *SMTPSender {
	if cfg.HELOName == "" {
		cfg.HELOName = "bridge.test"
	}
	cfg.LookupMX = func(context.Context, string) ([]*net.MX, error) {
		return []*net.MX{{Host: "localhost", Pref: 10}}, nil
	}
	cfg.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, serverAddr)
	}
	cfg.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	return NewSMTPSender(cfg)
}

func TestSMTPSenderMXHosts(t *testing.T) {
	ctx := context.Background()

	t.Run("sorted by preference, trailing dot trimmed", func(t *testing.T) {
		s := NewSMTPSender(SMTPSenderConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "backup.example.", Pref: 20}, {Host: "primary.example.", Pref: 10}}, nil
		}})
		hosts, err := s.mxHosts(ctx, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		if len(hosts) != 2 || hosts[0] != "primary.example" || hosts[1] != "backup.example" {
			t.Fatalf("hosts = %v, want [primary.example backup.example]", hosts)
		}
	})

	t.Run("no MX record falls back to the domain (implicit MX)", func(t *testing.T) {
		s := NewSMTPSender(SMTPSenderConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}})
		hosts, err := s.mxHosts(ctx, "example.com")
		if err != nil || len(hosts) != 1 || hosts[0] != "example.com" {
			t.Fatalf("mxHosts = (%v, %v), want [example.com]", hosts, err)
		}
	})

	t.Run("empty MX list falls back to the domain", func(t *testing.T) {
		s := NewSMTPSender(SMTPSenderConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return nil, nil
		}})
		hosts, err := s.mxHosts(ctx, "example.com")
		if err != nil || len(hosts) != 1 || hosts[0] != "example.com" {
			t.Fatalf("mxHosts = (%v, %v), want [example.com]", hosts, err)
		}
	})

	t.Run("null MX (RFC 7505) is rejected", func(t *testing.T) {
		s := NewSMTPSender(SMTPSenderConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: ".", Pref: 0}}, nil
		}})
		if _, err := s.mxHosts(ctx, "example.com"); err == nil {
			t.Fatal("a null MX must be rejected (domain accepts no mail)")
		}
	})
}

func TestSMTPSenderDelivers(t *testing.T) {
	addr, be := startRecordingServer(t, nil) // no TLS → cleartext delivery
	s := senderTo(addr, SMTPSenderConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := "Hello, world.\n.leading dot becomes dot-stuffed on the wire\n"
	if err := s.Deliver(ctx, "bridge@bridge.test", "alice@example.com", plainMsg("Hi there", body)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	msgs := be.recorded()
	if len(msgs) != 1 {
		t.Fatalf("server recorded %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.from != "bridge@bridge.test" {
		t.Errorf("MAIL FROM = %q, want bridge@bridge.test", m.from)
	}
	if len(m.rcpt) != 1 || m.rcpt[0] != "alice@example.com" {
		t.Errorf("RCPT TO = %v, want [alice@example.com]", m.rcpt)
	}
	for _, want := range []string{
		// Header names/addresses follow go-message's canonical output (angle-bracketed addr-spec,
		// "Mime-Version" casing) — all valid RFC 5322 (field names are case-insensitive).
		"From: <bridge@bridge.test>",
		"To: <alice@example.com>",
		"Subject: Hi there",
		"Mime-Version: 1.0",
		"Content-Transfer-Encoding: quoted-printable",
		"Hello, world.",
		".leading dot becomes dot-stuffed", // dot-unstuffed by the server: a single leading dot survives
	} {
		if !strings.Contains(m.data, want) {
			t.Errorf("delivered message missing %q.\n--- DATA ---\n%s", want, m.data)
		}
	}
}

func TestSMTPSenderSTARTTLS(t *testing.T) {
	addr, be := startRecordingServer(t, selfSignedTLS(t)) // advertises STARTTLS
	// RequireTLS=true → success proves STARTTLS actually happened (cleartext would be refused).
	s := senderTo(addr, SMTPSenderConfig{
		RequireTLS: true,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, // test-only: self-signed
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Deliver(ctx, "bridge@bridge.test", "bob@example.com", plainMsg("Secure", "over TLS")); err != nil {
		t.Fatalf("Deliver over STARTTLS: %v", err)
	}
	if got := be.recorded(); len(got) != 1 || got[0].rcpt[0] != "bob@example.com" {
		t.Fatalf("recorded = %+v, want one message to bob@example.com", got)
	}
}

func TestSMTPSenderRequireTLSRefused(t *testing.T) {
	addr, be := startRecordingServer(t, nil) // no TLS → no STARTTLS offered
	s := senderTo(addr, SMTPSenderConfig{RequireTLS: true})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.Deliver(ctx, "bridge@bridge.test", "bob@example.com", plainMsg("x", "y"))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("Deliver err = %v, want a STARTTLS-required failure", err)
	}
	if len(be.recorded()) != 0 {
		t.Fatal("no message must be delivered when STARTTLS is required but unavailable")
	}
}

func TestSMTPSenderHeaderInjectionRejected(t *testing.T) {
	s := NewSMTPSender(SMTPSenderConfig{}) // never dials — buildMessage rejects first
	ctx := context.Background()
	err := s.Deliver(ctx, "bridge@bridge.test", "bob@example.com", plainMsg("Hi\r\nBcc: evil@example.com", "body"))
	if err == nil || !strings.Contains(err.Error(), "injection") {
		t.Fatalf("Deliver err = %v, want a header-injection rejection", err)
	}
}
