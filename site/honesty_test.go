package main

import (
	"html"
	"io/fs"
	"path/filepath"
	"regexp"
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
	faq, quickstart := content(t, "faq.md"), content(t, "quickstart.md")
	protocol := content(t, "protocol.md")

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

	t.Run("the protocol is not presented as a finished standard", func(t *testing.T) {
		// Formal versioning and a conformance suite do not exist yet; the technical page says so
		// where it describes the protocol's status.
		if !strings.Contains(protocol, "snapshot of the reference implementation") || !strings.Contains(protocol, "roadmap") {
			t.Error("protocol.md no longer says the protocol is a snapshot with versioning and conformance on the roadmap")
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

}

// renderedText returns the visible text of every built page, keyed by its path in the output:
// the body with tags stripped and entities decoded, and a ¶ wherever a block (heading, paragraph,
// list item, cell, code block) ends, so a sentence never runs on into the next heading. The claims live in templates (home.html,
// protocol.html) and Go (the landing's steps) as well as markdown, so the sweeps below read what
// is published rather than one kind of source.
func renderedText(t *testing.T) map[string]string {
	t.Helper()
	out, read := buildInto(t)
	tags := regexp.MustCompile(`(?s)<[^>]*>`)
	blockEnd := regexp.MustCompile(`</(h[1-6]|p|li|td|th|summary|pre|dt|dd)>`)
	pages := map[string]string{}
	err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		rel, _ := filepath.Rel(out, path)
		page := read(rel)
		if i := strings.Index(page, "<body"); i >= 0 {
			page = page[i:]
		}
		page = blockEnd.ReplaceAllString(page, " ¶ ")
		pages[rel] = normalise(html.UnescapeString(tags.ReplaceAllString(page, " ")))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

// TestRenderedPagesMakeNoBannedClaims runs the phrase bans over every published page.
func TestRenderedPagesMakeNoBannedClaims(t *testing.T) {
	banned := []struct{ phrase, why string }{
		// `fleet=` in the _dmcn record defers hosting to another domain's nodes; that is how a
		// provider serves a customer's domain.
		{"nobody else's", "a domain can delegate hosting with `fleet=`"},
		{"domain's own servers", "a domain can delegate hosting with `fleet=`"},
		{"domain's own nodes", "a domain can delegate hosting with `fleet=`"},
		// DMCNP's root of trust IS DNS (the _dmcn fingerprint), the same anchor MTA-STS and DANE
		// use. Claiming otherwise would be the single most damaging thing this site could say.
		{"keyless trust", "the trust anchor is the _dmcn DNS record"},
		{"without dns", "the trust anchor is the _dmcn DNS record"},
		{"no dns dependency", "the trust anchor is the _dmcn DNS record"},
	}
	for page, text := range renderedText(t) {
		lower := strings.ToLower(text)
		for _, b := range banned {
			if strings.Contains(lower, b.phrase) {
				t.Errorf("%s says %q: %s", page, b.phrase, b.why)
			}
		}
	}
}

// approvedDHT is every sentence on the site that mentions a DHT, each checked to say the protocol
// has none (discovery is seeded from DNS; the DHT registry was removed). A new or reworded
// sentence fails until someone has read it and added it here.
var approvedDHT = map[string]bool{
	// protocol.md
	"Discovery is seeded from DNS, with no DHT, on purpose.":                                           true,
	"Most decentralised messaging puts identity in a shared overlay: a DHT, a chain, a consensus set.": true,
	// faq.md
	"Is there a blockchain, a DHT, or a global directory?":              true,
	"An earlier version did resolve identities through a Kademlia DHT.": true,
	// SPEC.md, rendered at /spec/
	`DMCN (the Decentralized Mesh Communication Network) is a peer-to-peer, end-to-end-encrypted store-and-forward mail network where cryptographic identity replaces SMTP-style trust ; the DMCN Protocol (DMCNP), specified here, is what its participants speak: every address is an Ed25519+X25519 keypair whose self-certifying record is served by the address's own domain fleet and discovered via DNS ("MX for identity" — no global DHT), and mail is hybrid-encrypted client-side and parked in recipient-designated relays' mailboxes.`: true,
	"0 — STORE / FETCH / mailbox / onion / resolve │ trust / federation Credential PKI (DNS-anchored DAR), /dmcn/join handshake │ transport libp2p streams (no DHT — discovery is DNS-seeded)": true,
}

func TestDHTIsOnlyNamedAsAbsent(t *testing.T) {
	sentence := regexp.MustCompile(`[^.?!¶]*\bDHT[^.?!¶]*[.?!]?`)
	for page, text := range renderedText(t) {
		for _, s := range sentence.FindAllString(text, -1) {
			if s = strings.TrimSpace(s); !approvedDHT[s] {
				t.Errorf("%s mentions a DHT in a sentence nobody has checked: %q\nIf it says the protocol has none, add it to approvedDHT.", page, s)
			}
		}
	}
}
