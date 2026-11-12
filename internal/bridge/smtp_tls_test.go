package bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// selfSignedTLS builds a throwaway server tls.Config for localhost.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
}

func startTLSServer(t *testing.T, tlsOpts *smtpTLS) string {
	t.Helper()
	srv := NewSMTPServer(context.Background(), "127.0.0.1:0", &InboundHandler{}, "bridge.localhost", newInboundLimits(0, 0, 0), tlsOpts, nil, testLogr())
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })
	return srv.Addr()
}

func clientTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"} // test-only: self-signed
}

// With require-TLS, MAIL FROM is refused on a plaintext connection and accepted
// once the client upgrades via STARTTLS.
func TestSMTPRequireTLS(t *testing.T) {
	addr := startTLSServer(t, &smtpTLS{config: selfSignedTLS(t), require: true})

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Mail("ext@gmail.com", nil); err == nil {
		t.Fatal("MAIL before STARTTLS must be rejected when TLS is required")
	}
	c.Close()

	c2, err := smtp.DialStartTLS(addr, clientTLS())
	if err != nil {
		t.Fatalf("dial+starttls: %v", err)
	}
	defer c2.Close()
	if err := c2.Mail("ext@gmail.com", nil); err != nil {
		t.Fatalf("MAIL after STARTTLS should pass: %v", err)
	}
}

// Implicit TLS (SMTPS): the listener speaks TLS from the first byte.
func TestSMTPImplicitTLS(t *testing.T) {
	addr := startTLSServer(t, &smtpTLS{config: selfSignedTLS(t), implicit: true})

	c, err := smtp.DialTLS(addr, clientTLS())
	if err != nil {
		t.Fatalf("dial tls: %v", err)
	}
	defer c.Close()
	if err := c.Mail("ext@gmail.com", nil); err != nil {
		t.Fatalf("MAIL over implicit TLS should pass: %v", err)
	}
}

// buildSMTPTLS rejects require/implicit TLS without a certificate, and accepts a
// valid cert/key pair.
func TestBuildSMTPTLS(t *testing.T) {
	if _, err := buildSMTPTLS(Config{}); err != nil {
		t.Fatalf("plaintext (no TLS) should be allowed: %v", err)
	}
	if _, err := buildSMTPTLS(Config{RequireTLS: true}); err == nil {
		t.Fatal("require-tls without a cert must error")
	}
	if _, err := buildSMTPTLS(Config{TLSCertFile: "cert.pem"}); err == nil {
		t.Fatal("cert without key must error")
	}

	// A ready-made config (the daemon passes its ACME manager's) is used as-is, and satisfies
	// require-TLS on its own.
	tc := selfSignedTLS(t)
	got, err := buildSMTPTLS(Config{TLSConfig: tc, RequireTLS: true})
	if err != nil || got == nil || got.config != tc || !got.require {
		t.Fatalf("TLSConfig should be used as the listener's config: %+v, %v", got, err)
	}
	if _, err := buildSMTPTLS(Config{TLSConfig: tc, TLSCertFile: "cert.pem", TLSKeyFile: "key.pem"}); err == nil {
		t.Fatal("a TLS config AND cert files is ambiguous and must error")
	}
}

// A listener built from Config.TLSConfig advertises STARTTLS and completes the upgrade.
func TestSMTPStartTLSFromConfig(t *testing.T) {
	opts, err := buildSMTPTLS(Config{TLSConfig: selfSignedTLS(t)})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	addr := startTLSServer(t, opts)

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Hello("sender.example"); err != nil {
		t.Fatalf("ehlo: %v", err)
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		t.Fatal("STARTTLS must be advertised when a TLS config is set")
	}
	c.Close()

	c2, err := smtp.DialStartTLS(addr, clientTLS())
	if err != nil {
		t.Fatalf("dial+starttls: %v", err)
	}
	defer c2.Close()
	if err := c2.Mail("ext@gmail.com", nil); err != nil {
		t.Fatalf("MAIL after STARTTLS should pass: %v", err)
	}
}
