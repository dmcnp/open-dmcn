package main

import (
	"strings"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

func testRoot(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// TestBuildDARSetsTheGate is the regression for the bug this whole change came out of. The daemon
// used to sign an authority record with no policy flags and no reserved local-parts, which meant
// registry.AddressUsable failed open and IssueAddressCredential had no caller anywhere — so any
// self-signed record on a live domain was immediately usable, and postmaster@ was first-come.
// Both halves are load-bearing and neither is visible in normal operation.
func TestBuildDARSetsTheGate(t *testing.T) {
	dar, err := buildDAR("mesh.example", testRoot(t))
	if err != nil {
		t.Fatalf("buildDAR: %v", err)
	}
	if err := dar.Verify(); err != nil {
		t.Fatalf("the record does not verify: %v", err)
	}
	if !dar.RequiresCountersign() {
		t.Error("PolicyRequireCountersign is unset — the address gate fails open and the offline root is decorative")
	}
	for _, want := range []string{"postmaster", "countersign", "authority"} {
		if !dar.ReservesLocalPart(want) {
			t.Errorf("%s@ is not reserved", want)
		}
	}
}

// TestBuildDARIsDeterministic is what lets `domain publish` work at all. init, publish and dns each
// rebuild the record from the root key rather than storing it, so if the result varied — a
// timestamp, a map iteration — publish would push a record with a different fingerprint than the
// fp= already in DNS, and every resolver would reject the domain.
func TestBuildDARIsDeterministic(t *testing.T) {
	root := testRoot(t)
	first, err := buildDAR("mesh.example", root)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := buildDAR("mesh.example", root)
		if err != nil {
			t.Fatal(err)
		}
		if again.Fingerprint() != first.Fingerprint() {
			t.Fatalf("fingerprint changed between builds: %s vs %s — publish would contradict DNS",
				first.Fingerprint(), again.Fingerprint())
		}
		if again.Revision != first.Revision {
			t.Fatalf("revision changed between builds: %d vs %d", first.Revision, again.Revision)
		}
	}
}

// TestBuildDARIsPerDomain covers an operator running two domains from one root keystore.
//
// The two records share a fingerprint, and that is correct rather than a collision: fp= is
// SHA-256 over the root KEY, so one key legitimately anchors both. What must differ is the record
// itself — each names its own domain, and each is published under its own _dmcn.<domain>, which is
// what stops a record for one domain being served as the other's.
func TestBuildDARIsPerDomain(t *testing.T) {
	root := testRoot(t)
	a, err := buildDAR("one.example", root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildDAR("two.example", root)
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != "one.example" || b.Domain != "two.example" {
		t.Fatalf("records do not name their own domains: %q, %q", a.Domain, b.Domain)
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("one root key produced two fingerprints — fp= is a property of the key, not the domain")
	}
}

func TestDmcnTXT(t *testing.T) {
	got := dmcnTXT("mesh.example", "ABC123", []string{"/ip4/1.2.3.4/tcp/7400/p2p/xyz"}, nil)
	want := `_dmcn.mesh.example.  TXT  "dmcn-verification=v1; fp=ABC123; seed=/ip4/1.2.3.4/tcp/7400/p2p/xyz"`
	if got != want {
		t.Fatalf("dmcnTXT =\n  %s\nwant\n  %s", got, want)
	}
	if s := dmcnTXT("d", "FP", nil, nil); s != `_dmcn.d.  TXT  "dmcn-verification=v1; fp=FP"` {
		t.Fatalf("no-seed form = %s", s)
	}
}

// TestDmcnTXTCarriesBridges pins the token that makes outbound-to-legacy mail possible at all: it
// is how a sender discovers which peer will carry mail to the ordinary email world. A domain that
// omits it simply cannot send outside DMCN, so the token's exact spelling matters.
func TestDmcnTXTCarriesBridges(t *testing.T) {
	got := dmcnTXT("mesh.example", "FP",
		[]string{"/ip4/1.2.3.4/tcp/7400/p2p/xyz"},
		[]string{"/ip4/1.2.3.4/tcp/7400/p2p/xyz"})
	want := `_dmcn.mesh.example.  TXT  "dmcn-verification=v1; fp=FP; seed=/ip4/1.2.3.4/tcp/7400/p2p/xyz; bridge=/ip4/1.2.3.4/tcp/7400/p2p/xyz"`
	if got != want {
		t.Fatalf("dmcnTXT =\n  %s\nwant\n  %s", got, want)
	}
	// And a bridge with no seed is still well-formed — the two are independent tokens.
	if s := dmcnTXT("d", "FP", nil, []string{"/ip4/1.1.1.1/tcp/1/p2p/z"}); !strings.Contains(s, "bridge=/ip4/1.1.1.1/tcp/1/p2p/z") {
		t.Fatalf("bridge-only form = %s", s)
	}
}

// TestTXTCarriesTheRecordsOwnFingerprint keeps the DNS anchor and the record it anchors in step.
// They are produced by different commands and an operator publishes one while the node verifies
// against the other, so a mismatch would be invisible until federation failed.
func TestTXTCarriesTheRecordsOwnFingerprint(t *testing.T) {
	dar, err := buildDAR("mesh.example", testRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dmcnTXT("mesh.example", dar.Fingerprint(), nil, nil), dar.Fingerprint()) {
		t.Error("the TXT record does not carry the record's fingerprint")
	}
}
