package bridge

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// dkimSignedHeaders are the header fields covered by the outbound DKIM signature. "From" is
// mandatory (DMARC alignment); the rest pin the message's routing/format so a relay can't
// alter them without breaking the signature. Every one is emitted by buildMIME.
var dkimSignedHeaders = []string{
	"From", "To", "Subject", "Date", "Message-ID",
	"MIME-Version", "Content-Type", "Content-Transfer-Encoding",
}

// DKIMSigner signs outbound RFC 5322 messages with a domain key so receivers can verify the
// bridge as the legitimate originator (RFC 6376). Uses relaxed/relaxed canonicalization (so a
// signature survives benign whitespace/encoding changes in transit) and SHA-256.
type DKIMSigner struct {
	domain   string
	selector string
	key      crypto.Signer
}

// NewDKIMSigner builds a signer for d=domain, s=selector using key (RSA or Ed25519).
func NewDKIMSigner(domain, selector string, key crypto.Signer) (*DKIMSigner, error) {
	if domain == "" || selector == "" {
		return nil, fmt.Errorf("dkim: domain and selector are required")
	}
	if key == nil {
		return nil, fmt.Errorf("dkim: nil signing key")
	}
	switch key.Public().(type) {
	case *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("dkim: unsupported key type %T (want RSA or Ed25519)", key.Public())
	}
	return &DKIMSigner{domain: domain, selector: selector, key: key}, nil
}

// Sign returns msg with a prepended DKIM-Signature header. msg must be a complete RFC 5322
// message with CRLF line endings (as SMTPSender.buildMessage produces).
func (d *DKIMSigner) Sign(msg []byte) ([]byte, error) {
	var out bytes.Buffer
	opts := &dkim.SignOptions{
		Domain:                 d.domain,
		Selector:               d.selector,
		Signer:                 d.key,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             dkimSignedHeaders,
	}
	if err := dkim.Sign(&out, bytes.NewReader(msg), opts); err != nil {
		return nil, fmt.Errorf("dkim: sign: %w", err)
	}
	return out.Bytes(), nil
}

// public exposes the signer's public key for DNS-record rendering.
func (d *DKIMSigner) public() crypto.PublicKey { return d.key.Public() }

// GenerateDKIMKey creates a new DKIM signing key ("rsa" → RSA-2048, the universally-verified
// default; "ed25519" → RFC 8463, smaller but not yet verified by all receivers) and returns
// it alongside its PKCS#8 PEM encoding for at-rest storage.
func GenerateDKIMKey(algorithm string) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "", "rsa", "rsa2048":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		key = k
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		key = k
	default:
		return nil, nil, fmt.Errorf("dkim: unsupported algorithm %q (want \"rsa\" or \"ed25519\")", algorithm)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadDKIMKey reads a PEM private key (PKCS#8 or PKCS#1) and returns it as a crypto.Signer,
// rejecting anything that isn't an RSA or Ed25519 key.
func LoadDKIMKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("dkim: %s is not PEM-encoded", path)
	}
	var parsed any
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default: // "PRIVATE KEY" (PKCS#8) and anything else
		if parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("dkim: parse %s: %w", path, err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("dkim: %s holds a %T, not a signing key", path, parsed)
	}
	switch signer.Public().(type) {
	case *rsa.PublicKey, ed25519.PublicKey:
		return signer, nil
	default:
		return nil, fmt.Errorf("dkim: %s is a %T (want RSA or Ed25519)", path, signer.Public())
	}
}

// dkimPublicTXT returns the public-key TXT value to publish at
// <selector>._domainkey.<domain> for the given key (RFC 6376 / RFC 8463).
func dkimPublicTXT(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", err
		}
		return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
	case ed25519.PublicKey:
		// RFC 8463 §3: p= is the base64 of the raw 32-byte Ed25519 public key.
		return "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(k), nil
	default:
		return "", fmt.Errorf("dkim: unsupported public key type %T", pub)
	}
}

// txtChunks splits s into ≤255-byte quoted character-strings joined by spaces — the
// zone-file form a single logical TXT record longer than 255 bytes must take (an RSA-2048
// DKIM key exceeds it). A short string yields a single quoted token.
func txtChunks(s string) string {
	const max = 255
	var parts []string
	for len(s) > max {
		parts = append(parts, `"`+s[:max]+`"`)
		s = s[max:]
	}
	parts = append(parts, `"`+s+`"`)
	return strings.Join(parts, " ")
}

// DeliverabilityDNS renders the DNS records an operator must publish for the bridge to exchange
// mail with the legacy world: MX so mail can arrive, SPF/DKIM/DMARC so what leaves is accepted,
// and the reverse-DNS (PTR) requirement that lives outside the domain's own zone.
//
// signer may be nil (the DKIM section then points at `dkim-keygen`); an empty publicIP or helo
// renders a placeholder or falls back to the domain.
//
// Note which name goes where, because it is the thing operators get wrong: SPF, DKIM (d=) and
// DMARC all hang off bridgeDomain, because DMARC alignment compares them against the From: header,
// which the bridge rewrites to @bridgeDomain. The MX target, the HELO name and the PTR are the
// HOST — often a subdomain like mail.example.com — and have nothing to do with alignment.
func DeliverabilityDNS(bridgeDomain, selector string, signer *DKIMSigner, helo, publicIP string) string {
	ip := publicIP
	if ip == "" {
		ip = "<your-sending-ip>"
	}
	if helo == "" {
		helo = bridgeDomain
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Bridge mail DNS — publish these records for %s:\n\n", bridgeDomain)

	fmt.Fprintf(&b, "  ; MX — where legacy mail for @%s is delivered (inbound)\n", bridgeDomain)
	fmt.Fprintf(&b, "  %s.\tIN MX\t10 %s.\n\n", bridgeDomain, helo)

	fmt.Fprintf(&b, "  ; SPF — authorize the bridge's sending IP (envelope MAIL FROM is @%s)\n", bridgeDomain)
	fmt.Fprintf(&b, "  %s.\tIN TXT\t\"v=spf1 ip4:%s -all\"\n\n", bridgeDomain, ip)

	if signer != nil {
		if val, err := dkimPublicTXT(signer.public()); err == nil {
			fmt.Fprintf(&b, "  ; DKIM — public key for selector %q (split into 255-byte strings)\n", selector)
			fmt.Fprintf(&b, "  %s._domainkey.%s.\tIN TXT\t%s\n\n", selector, bridgeDomain, txtChunks(val))
		}
	} else {
		fmt.Fprintf(&b, "  ; DKIM — no signing key loaded; run `dmcndcli bridge dkim-keygen --domain %s`\n"+
			"  ;   and set DMCND_BRIDGE_DKIM_KEY to the file it writes\n\n", bridgeDomain)
	}

	fmt.Fprintf(&b, "  ; DMARC — start at quarantine, tighten to p=reject once SPF+DKIM verify\n")
	fmt.Fprintf(&b, "  _dmarc.%s.\tIN TXT\t\"v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:dmarc@%s\"\n\n", bridgeDomain, bridgeDomain)

	fmt.Fprintf(&b, "  ; Reverse DNS (PTR) — set by your IP/hosting provider, NOT in this zone:\n")
	fmt.Fprintf(&b, "  ;   the PTR for %s must resolve to %q, and %q must have an A/AAAA record\n", ip, helo, helo)
	fmt.Fprintf(&b, "  ;   resolving back to %s (forward-confirmed reverse DNS).\n", ip)
	return b.String()
}
