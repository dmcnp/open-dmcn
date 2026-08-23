package bridge

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// txtLookupFor returns a dkim.VerifyOptions.LookupTXT that serves `value` for the expected
// <selector>._domainkey.<domain> name and errors on anything else.
func txtLookupFor(t *testing.T, domain, selector, value string) func(string) ([]string, error) {
	t.Helper()
	want := selector + "._domainkey." + domain
	return func(name string) ([]string, error) {
		if name != want {
			return nil, fmt.Errorf("unexpected DKIM lookup %q (want %q)", name, want)
		}
		return []string{value}, nil
	}
}

func TestDKIMSignVerifyRoundTrip(t *testing.T) {
	for _, algo := range []string{"rsa", "ed25519"} {
		t.Run(algo, func(t *testing.T) {
			signer, pemBytes, err := GenerateDKIMKey(algo)
			if err != nil {
				t.Fatalf("GenerateDKIMKey: %v", err)
			}
			if !bytes.Contains(pemBytes, []byte("PRIVATE KEY")) {
				t.Fatalf("generated PEM does not look like a private key: %q", pemBytes[:40])
			}
			const domain, selector = "bridge.test", "sel1"
			ds, err := NewDKIMSigner(domain, selector, signer)
			if err != nil {
				t.Fatalf("NewDKIMSigner: %v", err)
			}

			// Build a real MIME message (CRLF) the way SMTPSender does, then sign it.
			msg, err := buildMIME("alice@"+domain, "bob@example.com",
				plainMsg("Round trip", "Hello,\nthis is the body.\n"), time.Unix(1_700_000_000, 0).UTC())
			if err != nil {
				t.Fatalf("buildMIME: %v", err)
			}
			signed, err := ds.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.HasPrefix(signed, []byte("DKIM-Signature:")) {
				t.Fatalf("signed message does not start with a DKIM-Signature header")
			}

			txt, err := dkimPublicTXT(signer.Public())
			if err != nil {
				t.Fatalf("dkimPublicTXT: %v", err)
			}
			verifs, err := dkim.VerifyWithOptions(bytes.NewReader(signed), &dkim.VerifyOptions{
				LookupTXT: txtLookupFor(t, domain, selector, txt),
			})
			if err != nil {
				t.Fatalf("VerifyWithOptions: %v", err)
			}
			if len(verifs) != 1 {
				t.Fatalf("got %d verifications, want 1", len(verifs))
			}
			if verifs[0].Err != nil {
				t.Fatalf("DKIM signature did not verify: %v", verifs[0].Err)
			}
			if verifs[0].Domain != domain {
				t.Fatalf("verified d=%q, want %q", verifs[0].Domain, domain)
			}
		})
	}
}

// TestDKIMDeliveredMessageVerifies is the on-the-wire proof: a DKIM-configured SMTPSender
// delivers through a real go-smtp server (so the message survives DATA dot-stuffing/CRLF
// transport), and the captured message still verifies. Catches any canonicalization mismatch.
func TestDKIMDeliveredMessageVerifies(t *testing.T) {
	signer, _, err := GenerateDKIMKey("rsa")
	if err != nil {
		t.Fatal(err)
	}
	const domain, selector = "bridge.test", "wire"
	ds, err := NewDKIMSigner(domain, selector, signer)
	if err != nil {
		t.Fatal(err)
	}

	addr, be := startRecordingServer(t, nil)
	s := senderTo(addr, SMTPSenderConfig{HELOName: domain, DKIM: ds})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := "Body with a .leading-dot line\nand a second line.\n"
	if err := s.Deliver(ctx, "alice@"+domain, "bob@example.com", plainMsg("Signed + delivered", body)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	msgs := be.recorded()
	if len(msgs) != 1 {
		t.Fatalf("recorded %d messages, want 1", len(msgs))
	}
	txt, _ := dkimPublicTXT(signer.Public())
	verifs, err := dkim.VerifyWithOptions(strings.NewReader(msgs[0].data), &dkim.VerifyOptions{
		LookupTXT: txtLookupFor(t, domain, selector, txt),
	})
	if err != nil {
		t.Fatalf("VerifyWithOptions: %v", err)
	}
	if len(verifs) != 1 || verifs[0].Err != nil {
		t.Fatalf("delivered message failed DKIM verification: %+v", verifs)
	}
}

// TestSMTPSenderDKIMForByDomain checks the multi-tenant signer selection: the DKIM signer is
// chosen by the From (bridge) domain so d= aligns with From, falling back to the default.
func TestSMTPSenderDKIMForByDomain(t *testing.T) {
	mk := func(domain string) *DKIMSigner {
		key, _, err := GenerateDKIMKey("rsa")
		if err != nil {
			t.Fatal(err)
		}
		ds, err := NewDKIMSigner(domain, "sel", key)
		if err != nil {
			t.Fatal(err)
		}
		return ds
	}
	aliceDS, bobDS, defDS := mk("bridge.alice.com"), mk("bridge.bob.com"), mk("bridge.default")
	s := NewSMTPSender(SMTPSenderConfig{
		DKIM:         defDS,
		DKIMByDomain: map[string]*DKIMSigner{"bridge.alice.com": aliceDS, "bridge.bob.com": bobDS},
	})
	if s.dkimFor("carol@bridge.alice.com") != aliceDS {
		t.Fatal("From on bridge.alice.com must select alice's signer")
	}
	if s.dkimFor("carol@Bridge.Bob.COM") != bobDS {
		t.Fatal("signer lookup must be case-insensitive on the From domain")
	}
	if s.dkimFor("carol@bridge.other.com") != defDS {
		t.Fatal("an unmapped From domain must fall back to the default signer")
	}
}

func TestDKIMLoadKeyRoundTrip(t *testing.T) {
	for _, algo := range []string{"rsa", "ed25519"} {
		t.Run(algo, func(t *testing.T) {
			_, pemBytes, err := GenerateDKIMKey(algo)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "k.pem")
			if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			signer, err := LoadDKIMKey(path)
			if err != nil {
				t.Fatalf("LoadDKIMKey: %v", err)
			}
			if _, err := NewDKIMSigner("d.test", "s", signer); err != nil {
				t.Fatalf("loaded key not usable as a signer: %v", err)
			}
		})
	}
	t.Run("non-PEM rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.pem")
		_ = os.WriteFile(path, []byte("not pem"), 0o600)
		if _, err := LoadDKIMKey(path); err == nil {
			t.Fatal("LoadDKIMKey must reject non-PEM input")
		}
	})
}

func TestTxtChunks(t *testing.T) {
	short := txtChunks("short")
	if short != `"short"` {
		t.Fatalf("short chunk = %s, want \"short\"", short)
	}
	long := strings.Repeat("a", 600)
	got := txtChunks(long)
	// Three quoted strings: 255 + 255 + 90.
	if n := strings.Count(got, `"`); n != 6 {
		t.Fatalf("expected 3 quoted strings (6 quotes), got %d: %s", n, got)
	}
	// Stripping quotes + spaces must reproduce the original.
	if rejoined := strings.ReplaceAll(strings.ReplaceAll(got, `" "`, ""), `"`, ""); rejoined != long {
		t.Fatalf("rejoined chunks != original (len %d vs %d)", len(rejoined), len(long))
	}
}

func TestDeliverabilityDNS(t *testing.T) {
	signer, _, err := GenerateDKIMKey("rsa")
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := NewDKIMSigner("bridge.test", "sel", signer)
	out := DeliverabilityDNS("bridge.test", "sel", ds, "mx.bridge.test", []string{"203.0.113.7"})
	for _, want := range []string{
		"v=spf1 ip4:203.0.113.7 -all",
		"sel._domainkey.bridge.test.",
		"v=DKIM1; k=rsa; p=",
		"_dmarc.bridge.test.",
		"v=DMARC1; p=quarantine",
		"PTR for 203.0.113.7 must resolve to \"mx.bridge.test\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("DeliverabilityDNS output missing %q\n---\n%s", want, out)
		}
	}

	// With no signer, the DKIM section points at the keygen command and renders a placeholder IP.
	noKey := DeliverabilityDNS("bridge.test", "sel", nil, "", nil)
	if !strings.Contains(noKey, "dkim-keygen") || !strings.Contains(noKey, "<your-sending-ip>") {
		t.Errorf("no-signer output should mention dkim-keygen + a placeholder IP:\n%s", noKey)
	}
}
