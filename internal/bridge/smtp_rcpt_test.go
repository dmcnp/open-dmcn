package bridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-smtp"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/registry"
)

// startRcptServer brings up a real SMTP listener whose handler resolves addresses through lookup
// and records every delivery by recipient address.
func startRcptServer(t *testing.T, lookup LookupFunc) (addr string, delivered func() map[string]int) {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var mu sync.Mutex
	got := map[string]int{}
	h := NewInboundHandler(InboundConfig{
		BridgeKP:     kp,
		BridgeAddr:   "bridge@bridge.localhost",
		AuthVerifier: &StubAuthVerifier{DefaultSPF: SPFPass, DefaultDKIM: DKIMPass, DefaultDMARC: DMARCPass},
		Lookup:       lookup,
		Deliver: func(_ context.Context, rec *identity.IdentityRecord, _ *message.EncryptedEnvelope) error {
			mu.Lock()
			defer mu.Unlock()
			got[rec.Address]++
			return nil
		},
		BridgeDomain: "bridge.localhost",
		DMCNDomain:   "dmcn.localhost",
		Log:          testLogr(),
	})
	srv := NewSMTPServer(context.Background(), "127.0.0.1:0", h, "bridge.localhost", newInboundLimits(0, 0, 0), nil, nil, testLogr())
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })
	return srv.Addr(), func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string]int, len(got))
		for k, v := range got {
			out[k] = v
		}
		return out
	}
}

// registered resolves the given DMCN addresses to fresh records; anything else is not found, and
// "flaky@dmcn.localhost" fails as an unreachable fleet would.
func registered(t *testing.T, addrs ...string) LookupFunc {
	recs := map[string]*identity.IdentityRecord{}
	for _, a := range addrs {
		kp, err := identity.GenerateIdentityKeyPair()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		recs[a] = &identity.IdentityRecord{Address: a, Ed25519Public: kp.Ed25519Public, X25519Public: kp.X25519Public}
	}
	return func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == "flaky@dmcn.localhost" {
			return nil, errors.New("dial fleet: connection refused")
		}
		if rec, ok := recs[addr]; ok {
			return rec, nil
		}
		return nil, fmt.Errorf("%w: %s", registry.ErrNotFound, addr)
	}
}

func smtpCode(err error) int {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

// A sending MTA batches every recipient behind our MX into one transaction. Each RCPT TO must
// get its own copy — the session used to keep only the last one and drop the rest after a 250.
// An unknown recipient is refused at RCPT (550) without disturbing the others, and a fleet that
// cannot be reached is a temporary refusal (451), never a permanent one.
func TestSMTPEveryRecipientDelivered(t *testing.T) {
	addr, delivered := startRcptServer(t, registered(t, "alice@dmcn.localhost", "bob@dmcn.localhost"))

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.Mail("carol@gmail.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := c.Rcpt("alice@bridge.localhost", nil); err != nil {
		t.Fatalf("RCPT alice: %v", err)
	}
	if err := c.Rcpt("ghost@bridge.localhost", nil); smtpCode(err) != 550 {
		t.Fatalf("RCPT unknown: want 550, got %v", err)
	}
	if err := c.Rcpt("flaky@bridge.localhost", nil); smtpCode(err) != 451 {
		t.Fatalf("RCPT with unreachable fleet: want 451, got %v", err)
	}
	if err := c.Rcpt("bob@bridge.localhost", nil); err != nil {
		t.Fatalf("RCPT bob: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if _, err := w.Write([]byte(strings.ReplaceAll("From: carol@gmail.com\nTo: alice@bridge.localhost, bob@bridge.localhost\nSubject: hi\n\nhello\n", "\n", "\r\n"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("end DATA: %v", err)
	}

	got := delivered()
	want := map[string]int{"alice@dmcn.localhost": 1, "bob@dmcn.localhost": 1}
	if len(got) != len(want) || got["alice@dmcn.localhost"] != 1 || got["bob@dmcn.localhost"] != 1 {
		t.Fatalf("delivered %v, want %v", got, want)
	}

	// The next transaction on the same connection starts with no recipients left over.
	if err := c.Mail("carol@gmail.com", nil); err != nil {
		t.Fatalf("second MAIL FROM: %v", err)
	}
	if err := c.Rcpt("bob@bridge.localhost", nil); err != nil {
		t.Fatalf("second RCPT: %v", err)
	}
	w, err = c.Data()
	if err != nil {
		t.Fatalf("second DATA: %v", err)
	}
	if _, err := w.Write([]byte("Subject: again\r\n\r\nhello\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("end second DATA: %v", err)
	}
	got = delivered()
	if got["alice@dmcn.localhost"] != 1 || got["bob@dmcn.localhost"] != 2 {
		t.Fatalf("after second transaction delivered %v, want alice=1 bob=2", got)
	}
}
