package main

import (
	"flag"
	"fmt"
	"os"

	"dmcn.dev/open-dmcn/internal/bridge"
)

// cmdDKIMKeygen mints an outbound DKIM signing key and prints the DNS record that makes it mean
// something.
//
// Both halves matter. A key with no published record is worse than no key at all: the bridge
// signs every message with a selector receivers cannot resolve, and a DKIM signature that fails
// to verify is a stronger spam signal than an unsigned message. So the record is printed here,
// next to the key, rather than left as an exercise.
//
// This runs anywhere — it touches no network and no domain root. The key is the BRIDGE's, not the
// domain's: losing it costs a re-key and a DNS update, nothing more.
//
// --domain is the DOMAIN mail is from (the d= value), not the host serving anything. If addresses
// are user@example.com then d=example.com, even when the bridge runs on mail.example.com and the
// webmail is served from somewhere else again — DMARC compares d= against the From: header, and
// the bridge rewrites From: to @<domain>. The host goes in --host, which sets the MX target, the
// EHLO name and the PTR target.
func cmdDKIMKeygen(args []string) error {
	fs := flag.NewFlagSet("bridge dkim-keygen", flag.ExitOnError)
	domain := fs.String("domain", os.Getenv("DMCND_BRIDGE_DOMAIN"), "the email domain outbound mail is sent from (defaults to DMCND_BRIDGE_DOMAIN, else DMCND_DOMAIN)")
	selector := fs.String("selector", envOr("DMCND_BRIDGE_DKIM_SELECTOR", "dmcn"), "DKIM selector — the <selector>._domainkey label")
	algorithm := fs.String("algorithm", "rsa", `"rsa" (RSA-2048, verified everywhere) or "ed25519" (RFC 8463, smaller, not yet universally verified)`)
	out := fs.String("out", "dkim.pem", "file to write the private key to")
	force := fs.Bool("force", false, "overwrite an existing key file")
	helo := fs.String("host", os.Getenv("DMCND_BRIDGE_HELO"), "the HOST running the bridge — the MX target, EHLO name and PTR target (e.g. mail.example.com). Defaults to the domain itself")
	ip := fs.String("ip", "", "the bridge's public sending IP, so the SPF and PTR lines are pasteable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		*domain = os.Getenv("DMCND_DOMAIN")
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_BRIDGE_DOMAIN / DMCND_DOMAIN) — it is the d= your signature aligns to")
	}
	// Refuse to clobber: re-keying invalidates every signature made under the old key until the
	// new record propagates, so it should be a decision rather than a slip.
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s already exists.\n"+
			"  Re-keying means republishing the DNS record, and mail signed with the old key fails to\n"+
			"  verify until the new record propagates. Pass --force if you mean to.", *out)
	}

	signer, pemBytes, err := bridge.GenerateDKIMKey(*algorithm)
	if err != nil {
		return err
	}
	// 0600: this key lets anyone holding it sign mail as your domain.
	if err := os.WriteFile(*out, pemBytes, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	dkimSigner, err := bridge.NewDKIMSigner(*domain, *selector, signer)
	if err != nil {
		return err
	}

	fmt.Print(bridge.DeliverabilityDNS(*domain, *selector, dkimSigner, *helo, *ip))
	fmt.Fprintf(os.Stderr, "\nWrote %s (%s). On the node:\n"+
		"    DMCND_BRIDGE_DKIM_KEY=%s\n"+
		"    DMCND_BRIDGE_DKIM_SELECTOR=%s\n"+
		"If the bridge runs on a host other than %s, pass --host (e.g. mail.%s) so the MX and PTR\n"+
		"lines name it. Publish the records above before sending — an unresolvable selector is worse than no\n"+
		"signature at all, because a DKIM failure is a stronger spam signal than its absence.\n",
		*out, *algorithm, *out, *selector, *domain, *domain)
	return nil
}
