package main

import (
	"strings"
	"testing"
)

// normalise collapses runs of whitespace to single spaces. Every pin below matches against the
// normalised text, so re-wrapping a paragraph — which is what a copy edit does — cannot break the
// test for a reason that has nothing to do with meaning.
func normalise(s string) string { return strings.Join(strings.Fields(s), " ") }

// content reads one markdown source through the same embedded FS the build uses, so the test
// cannot drift from what is actually published.
func content(t *testing.T, name string) string {
	t.Helper()
	b, err := siteFS.ReadFile("content/" + name)
	if err != nil {
		t.Fatalf("read content/%s: %v", name, err)
	}
	return normalise(string(b))
}

// TestHonestClaims pins the claims that are easy to overstate and expensive to get wrong.
//
// It exists because a copy edit is the cheapest way to make this project lie. Every case below is
// a real regression that shipped: the FAQ claimed an operator "can't change who you are" while
// SPEC.md said the opposite two pages over; the quickstart claimed inbound mail was checked with
// SPF/DKIM/DMARC when the daemon it told you to run always installed a stub; the site said a
// domain is served by "its own nodes and nobody else's" while the spec documents `fleet=`
// delegation. Nothing else in the suite would have caught any of them — site_test.go pins build
// mechanics, not meaning.
//
// Rule of thumb when this test fails: the code changed, so either the claim is now true (update
// the pin) or the copy is now wrong (fix the copy). Never delete a case to make it pass.
func TestHonestClaims(t *testing.T) {
	index, faq, quickstart := content(t, "index.md"), content(t, "faq.md"), content(t, "quickstart.md")

	t.Run("no absolute claim that an operator cannot re-bind an address", func(t *testing.T) {
		// The domain ROOT can free an address and let it be bound again — that is the same
		// mechanism that recovers a lost account, and it is exactly what admin key custody sells.
		// Only an operator's day-to-day keys are barred.
		for _, banned := range []string{
			"can't do is change who you are",
			"never get the ability to read your mail or impersonate you",
		} {
			if strings.Contains(faq, banned) {
				t.Errorf("faq.md claims %q — the domain root can re-bind an address, by design", banned)
			}
		}
		if !strings.Contains(faq, "root-signed tombstone") {
			t.Error("faq.md no longer explains that re-binding needs a root-signed tombstone")
		}
	})

	t.Run("no claim that a domain is served only by its own nodes", func(t *testing.T) {
		// `fleet=` in the _dmcn record explicitly defers hosting to another domain's nodes; that
		// is how a provider serves a customer's domain.
		for _, src := range []struct{ name, body string }{{"index.md", index}, {"faq.md", faq}} {
			if strings.Contains(src.body, "nobody else's") {
				t.Errorf("%s claims a domain is served by its own nodes and nobody else's — `fleet=` delegates hosting", src.name)
			}
		}
	})

	t.Run("bridge auth is not claimed beyond what the daemon does", func(t *testing.T) {
		// Real SPF/DKIM/DMARC is now the default (applyBridgeModes in cmd/dmcnd), so the claim is
		// allowed — but the stub mode must be disclosed wherever it is claimed, and outbound must
		// not be described as sending when it defaults to capturing in memory.
		if strings.Contains(quickstart, "SPF/DKIM/DMARC") && !strings.Contains(quickstart, "DMCND_BRIDGE_AUTH_MODE=stub") {
			t.Error("quickstart.md claims real SPF/DKIM/DMARC without disclosing the stub auth mode")
		}
		if !strings.Contains(quickstart, "DMCND_BRIDGE_DELIVERY_MODE=smtp") {
			t.Error("quickstart.md does not say outbound delivery is opt-in — a fresh install sends nothing")
		}
	})

	t.Run("bridged mail is never described as end-to-end encrypted", func(t *testing.T) {
		for _, src := range []struct{ name, body string }{{"faq.md", faq}, {"quickstart.md", quickstart}} {
			if !strings.Contains(src.body, "not end-to-end encrypted") {
				t.Errorf("%s dropped the caveat that mail crossing the bridge is TLS-in-transit only", src.name)
			}
		}
	})

	t.Run("onion routing carries its inert-below-three-relays caveat", func(t *testing.T) {
		if strings.Contains(faq, "onion routing") && !strings.Contains(faq, "three relays") {
			t.Error("faq.md offers onion routing without saying it is inert until a mesh has three relays")
		}
	})

	t.Run("production readiness is not overstated", func(t *testing.T) {
		if !strings.Contains(faq, "Is it production ready?") {
			t.Error("faq.md dropped the production-readiness question")
		}
		if !strings.Contains(faq, "proof of concept") {
			t.Error("faq.md no longer calls the reference server a proof of concept")
		}
	})

	t.Run("the DNS trust anchor is not disclaimed", func(t *testing.T) {
		// DMCNP's root of trust IS DNS (the _dmcn fingerprint), the same anchor MTA-STS and DANE
		// use. Claiming otherwise would be the single most damaging thing this site could say.
		for _, src := range []struct{ name, body string }{{"index.md", index}, {"faq.md", faq}} {
			for _, banned := range []string{"keyless trust", "without DNS", "no DNS dependency"} {
				if strings.Contains(strings.ToLower(src.body), banned) {
					t.Errorf("%s claims %q — the trust anchor is the _dmcn DNS record", src.name, banned)
				}
			}
		}
	})
}
