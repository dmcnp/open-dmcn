package bridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// refusingBackend answers every RCPT TO with one reply.
type refusingBackend struct{ reply *smtp.SMTPError }

func (b *refusingBackend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &refusingSession{reply: b.reply}, nil
}

type refusingSession struct{ reply *smtp.SMTPError }

func (s *refusingSession) Mail(string, *smtp.MailOptions) error { return nil }
func (s *refusingSession) Rcpt(string, *smtp.RcptOptions) error { return s.reply }
func (s *refusingSession) Data(io.Reader) error                 { return nil }
func (s *refusingSession) Reset()                               {}
func (s *refusingSession) Logout() error                        { return nil }

func startRefusingServer(t *testing.T, reply *smtp.SMTPError) string {
	t.Helper()
	srv := smtp.NewServer(&refusingBackend{reply: reply})
	srv.Domain = "localhost"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// The SMTP sender says which failures are worth another try: a 4xx reply, an unreachable server
// or a DNS lookup that timed out are deferrals; a 5xx reply, a domain that does not exist or a
// null MX are the recipient side's final answer.
func TestSMTPSenderMarksDeferrals(t *testing.T) {
	ctx := context.Background()
	msg := plainMsg("Hi", "hello")
	dialFails := func(err error) *SMTPSender {
		return NewSMTPSender(SMTPSenderConfig{
			LookupMX: func(context.Context, string) ([]*net.MX, error) {
				return []*net.MX{{Host: "mx.example.com", Pref: 10}}, nil
			},
			Dial: func(context.Context, string, string) (net.Conn, error) { return nil, err },
		})
	}

	for _, tc := range []struct {
		name     string
		sender   *SMTPSender
		deferred bool
	}{
		{"451 greylisting", senderTo(startRefusingServer(t, &smtp.SMTPError{Code: 451, Message: "try again later"}), SMTPSenderConfig{}), true},
		{"550 no such user", senderTo(startRefusingServer(t, &smtp.SMTPError{Code: 550, Message: "no such user"}), SMTPSenderConfig{}), false},
		{"connection refused", dialFails(&net.OpError{Op: "dial", Err: errors.New("connection refused")}), true},
		{"host does not exist", dialFails(&net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", IsNotFound: true}}), false},
		{"MX lookup timed out", NewSMTPSender(SMTPSenderConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true}
		}}), true},
		{"null MX", NewSMTPSender(SMTPSenderConfig{LookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: ".", Pref: 0}}, nil
		}}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sender.Deliver(ctx, "alice@bridge.test", "bob@example.com", msg, Audience{})
			if err == nil {
				t.Fatal("delivery succeeded")
			}
			if got := errors.Is(err, ErrDeliveryDeferred); got != tc.deferred {
				t.Fatalf("deferred = %v, want %v (err: %v)", got, tc.deferred, err)
			}
		})
	}
}

// startDroppingServer is a bare SMTP server that accepts one message and hangs up at QUIT
// without replying.
func startDroppingServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		say := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
		say("220 localhost ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case inData && line == ".":
				inData = false
				say("250 queued")
			case inData:
			case strings.HasPrefix(strings.ToUpper(line), "EHLO"):
				say("250 localhost")
			case strings.HasPrefix(strings.ToUpper(line), "DATA"):
				inData = true
				say("354 go ahead")
			case strings.HasPrefix(strings.ToUpper(line), "QUIT"):
				return // hang up without the 221
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String()
}

// The most preferred MX that answers speaks for the domain: a greylisting primary is "come back
// later" whatever a stale backup says — even a backup that no longer resolves or answers 554 —
// and a primary that refuses is final even if a backup would have taken the message.
func TestSMTPSenderPreferredMXDecides(t *testing.T) {
	reply := func(code int) string {
		return startRefusingServer(t, &smtp.SMTPError{Code: code, Message: fmt.Sprintf("%d from this host", code)})
	}
	gone := &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", IsNotFound: true}}
	for _, tc := range []struct {
		name            string
		primary, backup string // a server address, or "" for a host whose name does not resolve
		deferred        bool
	}{
		{"greylisting primary, backup gone", reply(451), "", true},
		{"greylisting primary, backup refuses", reply(451), reply(554), true},
		{"refusing primary, backup would queue", reply(550), reply(451), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts := map[string]string{"mx1.example.com": tc.primary, "mx2.example.com": tc.backup}
			s := NewSMTPSender(SMTPSenderConfig{
				HELOName: "bridge.test",
				LookupMX: func(context.Context, string) ([]*net.MX, error) {
					return []*net.MX{{Host: "mx1.example.com", Pref: 10}, {Host: "mx2.example.com", Pref: 20}}, nil
				},
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					server := hosts[strings.Split(addr, ":")[0]]
					if server == "" {
						return nil, gone
					}
					var d net.Dialer
					return d.DialContext(ctx, network, server)
				},
			})
			err := s.Deliver(context.Background(), "alice@bridge.test", "bob@example.com", plainMsg("Hi", "hello"), Audience{})
			if got := errors.Is(err, ErrDeliveryDeferred); got != tc.deferred {
				t.Fatalf("deferred = %v, want %v (err: %v)", got, tc.deferred, err)
			}
		})
	}
}

// Cancelling the delivery's context ends a session that is already connected, rather than
// leaving a stopping bridge to wait out the session deadline.
func TestSMTPSenderCancelEndsAConnectedSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { // a server that accepts and then says nothing
		conn, err := ln.Accept()
		if err == nil {
			t.Cleanup(func() { conn.Close() })
		}
	}()
	s := senderTo(ln.Addr().String(), SMTPSenderConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	err = s.Deliver(ctx, "alice@bridge.test", "bob@example.com", plainMsg("Hi", "hello"), Audience{})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("cancelled delivery took %s", took)
	}
	if !errors.Is(err, ErrDeliveryDeferred) {
		t.Fatalf("err = %v, want a deferral to retry after the restart", err)
	}
}
