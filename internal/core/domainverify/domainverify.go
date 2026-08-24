// Package domainverify implements DOMAIN_DNS domain-control verification for
// DMCN identities (SPEC.md §1) and the DNS-seeded discovery layer
// that is the registry's bootstrap root. A domain proves control
// by publishing a TXT record at _dmcn.<domain> carrying the fingerprint of its
// root authority key, optionally a fleet deferral pointer, and (for a fleet
// domain) the bootstrap seed endpoints:
//
//		_dmcn.<domain>  TXT  "dmcn-verification=v1; fp=<40-hex fingerprint>[; fleet=<fleet-domain>][; seed=<multiaddr>]..."
//
//	  - fp=    the root-key fingerprint — the trust anchor for the domain's DAR.
//	           Non-transferable: copying it to another domain is useless without
//	           the matching private key.
//	  - fleet= a mailbox domain that runs no nodes of its own defers hosting to
//	           this fleet domain (email's MX delegation). Discovery only, not
//	           trust: records fetched from the fleet still verify against this
//	           domain's own fp. A spoofed fleet= is DoS-only.
//	  - seed=  bootstrap endpoint multiaddrs (each ending in /p2p/<peerID>, so the
//	           libp2p handshake authenticates the endpoint). Several for
//	           round-robin/failover — never a single pin. Published at the fleet
//	           domain and shared by every mailbox domain that defers to it.
//
// Seeds may be spread across multiple TXT strings (each still v1-prefixed) to fit
// the 255-char per-string limit; Resolve aggregates them. This package performs
// only the DNS lookup and parsing; it holds no network dependency beyond the
// standard resolver and is kept separate from the identity package so that
// package stays free of network I/O.
package domainverify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	// txtPrefix is prepended to a domain to form the verification record name.
	txtPrefix = "_dmcn."
	// scheme is the required leading token of a v1 verification record.
	scheme = "dmcn-verification=v1"
)

var (
	// ErrNoRecord means no _dmcn TXT record was found for the domain.
	ErrNoRecord = errors.New("domainverify: no _dmcn TXT record found")
	// ErrFingerprintMismatch means a record was found but none carried the
	// expected fingerprint.
	ErrFingerprintMismatch = errors.New("domainverify: fingerprint not present in _dmcn TXT record")
)

// lookupTXT resolves TXT records for a name. It is a package-level var so tests
// can inject a fake resolver, mirroring the protoMarshal/randReader override
// pattern used elsewhere in the codebase.
var lookupTXT = func(ctx context.Context, name string) ([]string, error) {
	var r net.Resolver
	return r.LookupTXT(ctx, name)
}

// DomainOf returns the domain portion of a local@domain address.
func DomainOf(address string) string {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// LocalPartOf returns the local part of a local@domain address ("" if malformed).
func LocalPartOf(address string) string {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// Verify reports whether _dmcn.<domain> publishes a v1 verification record whose
// fp= value equals fingerprint (case-insensitive). It returns nil on a match,
// ErrNoRecord if the name has no TXT records, ErrFingerprintMismatch if records
// exist but none carry the fingerprint, or the underlying lookup error.
func Verify(ctx context.Context, domain, fingerprint string) error {
	records, err := lookupTXT(ctx, txtPrefix+domain)
	if err != nil {
		return fmt.Errorf("domainverify: lookup %s%s: %w", txtPrefix, domain, err)
	}
	if len(records) == 0 {
		return ErrNoRecord
	}
	want := strings.ToUpper(strings.TrimSpace(fingerprint))
	for _, rec := range records {
		if fp, ok := parseFingerprint(rec); ok && fp == want {
			return nil
		}
	}
	return ErrFingerprintMismatch
}

// Record is the parsed contents of a domain's _dmcn TXT record set: its root-key
// fingerprint (trust anchor), an optional fleet-domain deferral pointer, and any
// bootstrap seed endpoints. A zero-value field means the token was absent. The JSON tags
// let it double as the static-_dmcn config file format (dev/CI + operator seed-pin).
type Record struct {
	// Fingerprint is the upper-cased fp= value (the DAR trust anchor); "" if absent.
	Fingerprint string `json:"fingerprint"`
	// Fleet is the fleet= deferral target (lower-cased); "" when the domain hosts
	// its own nodes (no deferral).
	Fleet string `json:"fleet,omitempty"`
	// Seeds are the seed= bootstrap multiaddrs, aggregated across all TXT strings.
	Seeds []string `json:"seeds,omitempty"`
	// Bridges are the bridge= endpoints (multiaddrs including /p2p/<peerID>) that carry this
	// domain's mail to and from the legacy email world — the DMCN analogue of an MX record.
	//
	// DISCOVERY ONLY. A tampered bridge= token points at a peer that cannot produce a
	// `bridge` credential signed by the domain's root, and is rejected before anything is
	// sealed to it. That matters more here than for seed=: a bridge decrypts outbound mail in
	// order to hand it to SMTP, so the credential check is the confidentiality boundary, not
	// merely a routing one.
	Bridges []string `json:"bridges,omitempty"`
}

// Resolve looks up _dmcn.<domain> and parses every v1 record into a single
// Record, aggregating seeds across strings. It returns ErrNoRecord when the name
// has no TXT records or none are v1 dmcn records, or the underlying lookup error.
func Resolve(ctx context.Context, domain string) (*Record, error) {
	records, err := lookupTXT(ctx, txtPrefix+domain)
	if err != nil {
		return nil, fmt.Errorf("domainverify: lookup %s%s: %w", txtPrefix, domain, err)
	}
	if len(records) == 0 {
		return nil, ErrNoRecord
	}
	out := &Record{}
	found := false
	for _, rec := range records {
		fp, fleet, seeds, bridges, ok := parseRecord(rec)
		if !ok {
			continue
		}
		found = true
		if fp != "" && out.Fingerprint == "" {
			out.Fingerprint = fp
		}
		if fleet != "" && out.Fleet == "" {
			out.Fleet = fleet
		}
		out.Seeds = append(out.Seeds, seeds...)
		out.Bridges = append(out.Bridges, bridges...)
	}
	if !found {
		return nil, ErrNoRecord
	}
	return out, nil
}

// parseRecord extracts the v1 tokens from one TXT string: the upper-cased fp=, the
// lower-cased fleet=, and any seed= / bridge= values. ok is false when the string is not
// a v1 dmcn record (so unrelated TXT records are ignored).
func parseRecord(rec string) (fp, fleet string, seeds, bridges []string, ok bool) {
	rec = strings.TrimSpace(rec)
	if !strings.HasPrefix(rec, scheme) {
		return "", "", nil, nil, false
	}
	ok = true
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "fp="):
			fp = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(part, "fp=")))
		case strings.HasPrefix(part, "fleet="):
			fleet = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(part, "fleet=")))
		case strings.HasPrefix(part, "seed="):
			if v := strings.TrimSpace(strings.TrimPrefix(part, "seed=")); v != "" {
				seeds = append(seeds, v)
			}
		case strings.HasPrefix(part, "bridge="):
			if v := strings.TrimSpace(strings.TrimPrefix(part, "bridge=")); v != "" {
				bridges = append(bridges, v)
			}
		}
	}
	return fp, fleet, seeds, bridges, ok
}

// parseFingerprint extracts and upper-cases the fp= value from a
// "dmcn-verification=v1; fp=<hex>" record, reporting whether it is a well-formed
// v1 record carrying an fp field.
func parseFingerprint(rec string) (string, bool) {
	fp, _, _, _, ok := parseRecord(rec)
	if !ok || fp == "" {
		return "", false
	}
	return fp, true
}
