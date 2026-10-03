package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// TestProtocolReference pins the facts an implementer reads /protocol/ for, and the structure that
// makes the page usable: every table of contents entry has its anchor, and the reference tables
// are the collapsible kind.
func TestProtocolReference(t *testing.T) {
	_, read := buildInto(t)
	page := read("protocol/index.html")

	for _, want := range []string{
		"/dmcn/relay/1.0.0", "dmcn-cek-wrap-v1", "dmcn-verification=v1", "dmcn-identity-self-v1",
		"get_relay_descriptor", "routing_credential", "ONION_REQUIRED",
		"<details data-ref", "data-toc-desk", "<details data-toc-mm",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("/protocol/ is missing %q", want)
		}
	}
	// The core reference documents the core: no extension wire names. (It does name a DHT, to say
	// why the protocol has none; honesty_test.go keeps it from claiming one.)
	for _, banned := range []string{"consume_send_inject", "set_quota", "FleetDomainPermit", "rate_steps", "rate_credential"} {
		if strings.Contains(page, banned) {
			t.Errorf("/protocol/ mentions %q", banned)
		}
	}
	// The reference sits inside the article, where the prose styles (and the scrolling table wrap
	// that keeps the page phone-width) apply. A stray closing tag in the template ends the
	// article early and the browser silently moves everything after it out.
	article := page[strings.Index(page, `<article class="prose">`):]
	article = article[:strings.Index(article, "</article>")]
	if strings.Count(article, "<div") != strings.Count(article, "</div>") {
		t.Errorf("/protocol/ article has %d <div> but %d </div>", strings.Count(article, "<div"), strings.Count(article, "</div>"))
	}
	if !strings.Contains(article, `id="onion"`) {
		t.Error("the last reference section is outside <article class=\"prose\">")
	}
	// get.dmcnmail.com/protocol used to host this reference and now 301s here; browsers carry the
	// #fragment across the redirect, so every section id it had must still exist.
	for _, id := range []string{"status", "identity", "resolution", "messages", "wire", "relay-ops", "trust", "signing", "onion"} {
		if !strings.Contains(page, `id="`+id+`"`) {
			t.Errorf("/protocol/ lost #%s, which old get.dmcnmail.com/protocol links still point at", id)
		}
	}
	// Every table of contents link lands on a heading on the page.
	for _, m := range regexp.MustCompile(`href="#([a-z0-9-]+)"`).FindAllStringSubmatch(page, -1) {
		if !strings.Contains(page, `id="`+m[1]+`"`) {
			t.Errorf("/protocol/ links #%s but has no element with that id", m[1])
		}
	}
	for _, s := range referenceSections {
		if !strings.Contains(page, `href="#`+s.ID+`"`) {
			t.Errorf("/protocol/ table of contents has no entry for %q", s.ID)
		}
		if strings.Count(page, `<h2 id="`+s.ID+`">`+s.Title+`<a class="hash" href="#`+s.ID+`"`) != 1 {
			t.Errorf("/protocol/ should render the %q heading exactly once, titled %q, with its # anchor", s.ID, s.Title)
		}
	}
	// The markdown half and the reference share one id namespace; a duplicate sends a link to
	// whichever comes first.
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(` id="([^"]+)"`).FindAllStringSubmatch(page, -1) {
		if seen[m[1]] {
			t.Errorf("/protocol/ has two elements with id=%q", m[1])
		}
		seen[m[1]] = true
	}
}

// TestLandingIsIntroductory keeps the home page for newcomers: what DMCNP is and why it exists.
// The record formats, the layer stack and the wire vocabulary live on /protocol/, which the
// landing links. Only the visible page is checked: the shared <head> carries an og:image:alt that
// describes the social card, which is a schema diagram.
func TestLandingIsIntroductory(t *testing.T) {
	_, read := buildInto(t)
	home := read("index.html")
	if i := strings.Index(home, "<body"); i >= 0 {
		home = home[i:]
	}
	for _, technical := range []string{"_dmcn", "TXT", "RelayHints", "libp2p", "X25519", "Ed25519", ".proto", "What you'd implement"} {
		if strings.Contains(home, technical) {
			t.Errorf("the landing page uses %q; technical detail belongs on /protocol/", technical)
		}
	}
	for _, link := range []string{`href="/protocol"`, `href="/quickstart"`} {
		if !strings.Contains(home, link) {
			t.Errorf("the landing page does not link %s", link)
		}
	}
	// Both sections are markdown (content/index.md), so they share the site's heading style and
	// each heading gets a # permalink, like every other page's. The "Why not ...?" answers are
	// linked from replies to those objections, so their ids have to keep working.
	for _, id := range []string{
		"why-it-exists", "what-it-is",
		"why-not-pgp", "why-not-smime", "why-not-spf-dkim-and-dmarc",
		"why-not-tls-between-mail-servers", "why-not-use-an-encrypted-email-service",
	} {
		if !regexp.MustCompile(`<h[23] id="` + id + `">[^<]+<a class="hash" href="#` + id + `"`).MatchString(home) {
			t.Errorf("the landing has no %q heading with its # permalink", id)
		}
	}
}

// TestBuildProtocolMatchesSchema: every field, op and enum value the schema declares has a note,
// and no note names something the schema no longer has. buildProtocol returns an error otherwise,
// which is what makes `make site` fail on a schema change the page does not reflect.
func TestBuildProtocolMatchesSchema(t *testing.T) {
	if _, err := buildProtocol(); err != nil {
		t.Fatal(err)
	}
}

// TestSchemaAuditCatchesDrift checks the audit itself: a field with no note and a note naming
// nothing are both reported.
func TestSchemaAuditCatchesDrift(t *testing.T) {
	md := (&dmcnpb.Credential{}).ProtoReflect().Descriptor()
	notes := map[string]string{}
	for k, v := range credentialNotes {
		notes[k] = v
	}
	delete(notes, "subject")
	notes["no_such_field"] = "stale"

	audit := &schemaAudit{}
	table := protoFieldTable("test", md, notes, audit)
	got := strings.Join(audit.problems, "\n")
	for _, want := range []string{`field "subject"`, `note for "no_such_field" matches no field`} {
		if !strings.Contains(got, want) {
			t.Errorf("audit did not report %s; got:\n%s", want, got)
		}
	}
	if len(table.Rows) < md.Fields().Len() {
		t.Errorf("table has %d rows for %d fields", len(table.Rows), md.Fields().Len())
	}
}

// TestReservedNumbersAllListed: every number a message or enum reserves has a "(reserved)" row,
// including numbers above the highest live one (Credential reserves 15 with 14 live fields). A
// reader who can't see a reserved number might reuse it.
func TestReservedNumbersAllListed(t *testing.T) {
	data, err := buildProtocol()
	if err != nil {
		t.Fatal(err)
	}
	fieldRanges := func(md protoreflect.MessageDescriptor) (out [][2]int) {
		for i := 0; i < md.ReservedRanges().Len(); i++ {
			r := md.ReservedRanges().Get(i)
			out = append(out, [2]int{int(r[0]), int(r[1]) - 1}) // FieldRanges end is exclusive
		}
		return out
	}
	enumRanges := func(ed protoreflect.EnumDescriptor) (out [][2]int) {
		for i := 0; i < ed.ReservedRanges().Len(); i++ {
			r := ed.ReservedRanges().Get(i)
			out = append(out, [2]int{int(r[0]), int(r[1])}) // EnumRanges end is inclusive
		}
		return out
	}
	for _, c := range []struct {
		table  specTable
		ranges [][2]int
	}{
		{data.IdentityFields, fieldRanges((&dmcnpb.IdentityRecord{}).ProtoReflect().Descriptor())},
		{data.EnvelopeFields, fieldRanges((&dmcnpb.EncryptedEnvelope{}).ProtoReflect().Descriptor())},
		{data.CredFields, fieldRanges((&dmcnpb.Credential{}).ProtoReflect().Descriptor())},
		{data.RotationFields, fieldRanges((&dmcnpb.RotationEntry{}).ProtoReflect().Descriptor())},
		{data.HistoryFields, fieldRanges((&dmcnpb.AddressHistoryRecord{}).ProtoReflect().Descriptor())},
		{data.RelayOps, fieldRanges((&dmcnpb.RelayRequest{}).ProtoReflect().Descriptor())},
		{data.Tiers, enumRanges(dmcnpb.VerificationTier(0).Descriptor())},
	} {
		listed := map[int]bool{}
		for _, row := range c.table.Rows {
			if row[1] != "(reserved)" {
				continue
			}
			lo, hi, _ := strings.Cut(row[0], "–")
			from, _ := strconv.Atoi(lo)
			to := from
			if hi != "" {
				to, _ = strconv.Atoi(hi)
			}
			for n := from; n <= to; n++ {
				listed[n] = true
			}
		}
		for _, r := range c.ranges {
			for n := r[0]; n <= r[1] && n < r[0]+1000; n++ {
				if !listed[n] {
					t.Errorf("%s: %d is reserved in the schema but has no (reserved) row", c.table.Ref, n)
				}
			}
		}
	}
}
