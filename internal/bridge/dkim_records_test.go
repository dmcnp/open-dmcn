package bridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dkim_records_test.go covers the pairing that actually matters to deliverability: the key written
// to disk and the public key printed for DNS must be halves of the same thing.
//
// Getting this wrong is silent and expensive. The bridge would sign every message, receivers would
// fetch a selector that resolves to a different key, and every signature would FAIL — which is a
// worse spam signal than sending unsigned, because a broken signature looks like forgery.

// TestGeneratedKeyMatchesItsPublishedRecord round-trips a generated key through the same path the
// daemon uses (write PEM → LoadDKIMKey → sign) and checks the DNS record advertises that key.
func TestGeneratedKeyMatchesItsPublishedRecord(t *testing.T) {
	for _, algo := range []string{"rsa", "ed25519"} {
		t.Run(algo, func(t *testing.T) {
			signer, pemBytes, err := GenerateDKIMKey(algo)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			path := filepath.Join(t.TempDir(), "dkim.pem")
			if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
				t.Fatal(err)
			}

			// What the CLI prints comes from the in-memory signer...
			printed, err := dkimPublicTXT(signer.Public())
			if err != nil {
				t.Fatalf("public TXT: %v", err)
			}
			// ...and what the daemon signs with comes from the file. They must agree, or the
			// published record describes a key nobody is signing with.
			loaded, err := LoadDKIMKey(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			fromDisk, err := dkimPublicTXT(loaded.Public())
			if err != nil {
				t.Fatalf("public TXT from disk: %v", err)
			}
			if printed != fromDisk {
				t.Fatalf("the printed record does not describe the key on disk:\nprinted: %s\non disk: %s", printed, fromDisk)
			}
		})
	}
}

// TestDeliverabilityRecordsCarryEverythingAnOperatorMustPublish pins the four things that decide
// whether outbound mail is accepted. Omitting any one of them is the difference between mail
// arriving and mail landing in spam, and none of them is guessable.
func TestDeliverabilityRecordsCarryEverythingAnOperatorMustPublish(t *testing.T) {
	signer, _, err := GenerateDKIMKey("rsa")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := NewDKIMSigner("merten.vg", "dmcn", signer)
	if err != nil {
		t.Fatal(err)
	}
	out := DeliverabilityDNS("merten.vg", "dmcn", ds, "", "")

	for _, want := range []string{
		"v=spf1",                    // SPF
		"dmcn._domainkey.merten.vg", // the DKIM record, at the right name
		"v=DKIM1",
		"_dmarc.merten.vg", // DMARC
		"v=DMARC1",
		"PTR", // reverse DNS, which is set at the provider and not in the zone
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the record set omits %q:\n%s", want, out)
		}
	}
}

// TestDeliverabilityWithoutAKeySaysHowToGetOne keeps the no-DKIM case actionable rather than
// merely incomplete — and names a command that exists in THIS repo. It previously pointed at
// `dmcn-bridge dkim-keygen`, which is a product binary and not shipped here.
func TestDeliverabilityWithoutAKeySaysHowToGetOne(t *testing.T) {
	out := DeliverabilityDNS("merten.vg", "dmcn", nil, "", "")
	if !strings.Contains(out, "dkim-keygen") {
		t.Errorf("no pointer to key generation:\n%s", out)
	}
	if strings.Contains(out, "dmcn-bridge") {
		t.Errorf("points at `dmcn-bridge`, which does not exist in this repo:\n%s", out)
	}
}
