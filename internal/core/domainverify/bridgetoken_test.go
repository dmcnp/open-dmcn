package domainverify

import "testing"

// bridgetoken_test.go covers the `bridge=` token — the DMCN analogue of an MX record, and the only
// way a sender learns which peer will carry its mail out to the ordinary email world.

// TestParseBridgeToken pins that bridge= is read, aggregated, and kept separate from seed=.
// Conflating the two would be quietly dangerous: a relay only ever holds sealed envelopes, but a
// bridge decrypts mail in order to hand it to SMTP.
func TestParseBridgeToken(t *testing.T) {
	_, _, seeds, bridges, ok := parseRecord(
		"dmcn-verification=v1; fp=ABC; seed=/ip4/1.1.1.1/tcp/7400/p2p/aaa; bridge=/ip4/2.2.2.2/tcp/7400/p2p/bbb")
	if !ok {
		t.Fatal("record not recognised as v1")
	}
	if len(seeds) != 1 || seeds[0] != "/ip4/1.1.1.1/tcp/7400/p2p/aaa" {
		t.Errorf("seeds = %v", seeds)
	}
	if len(bridges) != 1 || bridges[0] != "/ip4/2.2.2.2/tcp/7400/p2p/bbb" {
		t.Errorf("bridges = %v", bridges)
	}
}

// TestBridgeTokenIsOptional keeps a domain with no bridge working normally — it just cannot send
// to legacy email, which is a different thing from being broken.
func TestBridgeTokenIsOptional(t *testing.T) {
	_, _, _, bridges, ok := parseRecord("dmcn-verification=v1; fp=ABC; seed=/ip4/1.1.1.1/tcp/7400/p2p/aaa")
	if !ok {
		t.Fatal("record not recognised as v1")
	}
	if len(bridges) != 0 {
		t.Errorf("bridges = %v, want none", bridges)
	}
}

// TestMultipleBridges covers a domain advertising more than one, which is how an operator rolls a
// bridge over without an outage: both are listed, and a sender takes the first that proves itself.
func TestMultipleBridges(t *testing.T) {
	_, _, _, bridges, _ := parseRecord(
		"dmcn-verification=v1; fp=ABC; bridge=/ip4/1.1.1.1/tcp/1/p2p/a; bridge=/ip4/2.2.2.2/tcp/2/p2p/b")
	if len(bridges) != 2 {
		t.Fatalf("bridges = %v, want 2", bridges)
	}
}

// TestEmptyBridgeTokenIgnored keeps a malformed record from yielding an empty endpoint that would
// later fail deep in a dial with a useless error.
func TestEmptyBridgeTokenIgnored(t *testing.T) {
	_, _, _, bridges, _ := parseRecord("dmcn-verification=v1; fp=ABC; bridge=; bridge=   ")
	if len(bridges) != 0 {
		t.Errorf("bridges = %v, want none", bridges)
	}
}
