package bridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/mail"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// DNS access is funnelled through these overridable package vars (mirroring the
// lookupTXT / protoMarshal / randReader override pattern used elsewhere) so unit
// tests can exercise the full SPF/DKIM/DMARC logic with fake resolvers and never
// touch the network.
var (
	// authSPFCheck evaluates SPF for a sending IP, HELO identity, and envelope
	// sender. The default delegates to blitiri.com.ar/go/spf against the system
	// resolver.
	authSPFCheck = func(ctx context.Context, ip net.IP, helo, sender string) (spf.Result, error) {
		return spf.CheckHostWithSender(ip, helo, sender, spf.WithContext(ctx))
	}
	// authDKIMVerify verifies the DKIM signatures present on a raw RFC5322
	// message, returning one Verification per signature.
	authDKIMVerify = func(r io.Reader) ([]*dkim.Verification, error) {
		return dkim.Verify(r)
	}
	// authDMARCLookup resolves the DMARC policy record for a domain.
	authDMARCLookup = func(domain string) (*dmarc.Record, error) {
		return dmarc.Lookup(domain)
	}
)

// DNSAuthVerifier performs real SPF, DKIM, and DMARC verification against DNS.
// It is the production replacement for StubAuthVerifier (SPEC.md §7).
//
// Trust note: the bridge is the only party that runs these checks, at ingest,
// while the legacy message is in the clear. The signed BridgeClassificationRecord
// then carries the verdict; downstream DMCN recipients trust that verdict rather
// than re-running DKIM (see the bridge trust assumption in the README).
type DNSAuthVerifier struct{}

// NewDNSAuthVerifier returns a verifier that checks SPF/DKIM/DMARC against the
// real DNS.
func NewDNSAuthVerifier() *DNSAuthVerifier { return &DNSAuthVerifier{} }

// Verify runs SPF, DKIM, and DMARC over an inbound message. It never returns an
// error for ordinary authentication failures — those are reported as result
// codes in AuthResult; a non-nil error is reserved for inputs it cannot evaluate
// at all. senderIP is the connecting client's address (host or host:port), from
// is the SMTP MAIL FROM (envelope sender), and data is the raw RFC5322 message.
func (v *DNSAuthVerifier) Verify(ctx context.Context, senderIP, from string, data []byte) (*AuthResult, error) {
	res := &AuthResult{SenderIP: senderIP, SPF: SPFNone, DKIM: DKIMNone, DMARC: DMARCNone, DMARCPolicy: DMARCPolicyNone}

	envelopeDomain := domainOf(from)

	// SPF — evaluate the connecting IP against the envelope-sender domain.
	// A null sender (<>) or unparseable IP yields SPFNone (we have no captured
	// HELO identity to fall back to in the PoC's SMTP session).
	if ip := parseHost(senderIP); ip != nil && envelopeDomain != "" {
		if r, err := authSPFCheck(ctx, ip, envelopeDomain, strings.Trim(from, "<>")); err == nil || r != "" {
			res.SPF = mapSPFResult(r)
		}
	}

	// DKIM — verify every signature; remember which d= domains passed so DMARC
	// can check alignment.
	dkimPassDomains, dkimResult := verifyDKIM(data)
	res.DKIM = dkimResult

	// DMARC — keyed on the RFC5322.From header domain (the identity DMARC
	// protects), not the envelope sender.
	fromHeaderDomain := headerFromDomain(data)
	res.DMARC, res.DMARCPolicy = evalDMARC(envelopeDomain, fromHeaderDomain, res.SPF, dkimPassDomains)

	return res, nil
}

// verifyDKIM verifies the message's DKIM signatures, returning the set of d=
// domains whose signature validated and the overall DKIM result:
//   - no signatures present            → DKIMNone
//   - at least one valid signature     → DKIMPass
//   - signatures present, none valid   → DKIMFail
func verifyDKIM(data []byte) (passDomains []string, result DKIMResult) {
	verifs, err := authDKIMVerify(bytes.NewReader(data))
	if err != nil && len(verifs) == 0 {
		// Could not parse / evaluate any signature — treat as no DKIM rather
		// than a failure, so a malformed header alone is not "suspicious".
		return nil, DKIMNone
	}
	if len(verifs) == 0 {
		return nil, DKIMNone
	}
	for _, ver := range verifs {
		if ver.Err == nil {
			passDomains = append(passDomains, strings.ToLower(ver.Domain))
		}
	}
	if len(passDomains) > 0 {
		return passDomains, DKIMPass
	}
	return nil, DKIMFail
}

// evalDMARC looks up the From-domain's DMARC policy and evaluates alignment.
// It returns the DMARC result plus the published policy disposition (p=), which
// the bridge uses to decide whether a failure is a hard reject (see ShouldReject).
func evalDMARC(envelopeDomain, fromDomain string, spfRes SPFResult, dkimPassDomains []string) (DMARCResult, DMARCPolicy) {
	if fromDomain == "" {
		return DMARCNone, DMARCPolicyNone
	}
	rec, err := authDMARCLookup(fromDomain)
	if err != nil || rec == nil {
		// ErrNoPolicy (or any lookup failure) → domain publishes no DMARC.
		return DMARCNone, DMARCPolicyNone
	}
	policy := mapDMARCPolicy(rec.Policy)

	spfAligned := spfRes == SPFPass && domainsAligned(envelopeDomain, fromDomain, rec.SPFAlignment)
	dkimAligned := false
	for _, d := range dkimPassDomains {
		if domainsAligned(d, fromDomain, rec.DKIMAlignment) {
			dkimAligned = true
			break
		}
	}
	if spfAligned || dkimAligned {
		return DMARCPass, policy
	}
	return DMARCFail, policy
}

// domainsAligned reports whether two domains satisfy DMARC identifier alignment.
// Strict alignment requires an exact match; relaxed alignment requires the same
// organizational (registrable) domain.
func domainsAligned(a, b string, mode dmarc.AlignmentMode) bool {
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if mode == dmarc.AlignmentStrict {
		return false
	}
	return orgDomain(a) == orgDomain(b)
}

// orgDomain returns the effective registrable domain (eTLD+1) for a host,
// falling back to the input if the public-suffix lookup cannot resolve one.
func orgDomain(host string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

func mapSPFResult(r spf.Result) SPFResult {
	switch r {
	case spf.Pass:
		return SPFPass
	case spf.Fail:
		return SPFFail
	case spf.SoftFail:
		return SPFSoftFail
	case spf.Neutral:
		return SPFNeutral
	default:
		// None, TempError, PermError — no usable assertion.
		return SPFNone
	}
}

func mapDMARCPolicy(p dmarc.Policy) DMARCPolicy {
	switch p {
	case dmarc.PolicyReject:
		return DMARCPolicyReject
	case dmarc.PolicyQuarantine:
		return DMARCPolicyQuarantine
	default:
		return DMARCPolicyNone
	}
}

// parseHost parses an IP from a bare address or a host:port pair.
func parseHost(addr string) net.IP {
	if addr == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	return net.ParseIP(addr)
}

// domainOf returns the lower-cased domain of an email address, tolerating
// surrounding angle brackets (e.g. "<alice@example.com>").
func domainOf(addr string) string {
	addr = strings.Trim(strings.TrimSpace(addr), "<>")
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// headerFromDomain extracts the domain of the RFC5322 From header from a raw
// message, returning "" if it cannot be parsed.
func headerFromDomain(data []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	addr, err := mail.ParseAddress(msg.Header.Get("From"))
	if err != nil {
		return ""
	}
	return domainOf(addr.Address)
}
