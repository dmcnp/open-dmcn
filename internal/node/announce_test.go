package node

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

func mas(t *testing.T, ss ...string) []multiaddr.Multiaddr {
	t.Helper()
	var out []multiaddr.Multiaddr
	for _, s := range ss {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ma)
	}
	return out
}

// TestAnnounceDefaultsToDetected keeps every existing node unchanged: libp2p's own detection is
// right whenever the public address is on an interface, which is most self-hosts.
func TestAnnounceDefaultsToDetected(t *testing.T) {
	detected := mas(t, "/ip4/10.0.0.5/tcp/7400")
	got := announceFactory(nil)(detected)
	if len(got) != 1 || got[0].String() != "/ip4/10.0.0.5/tcp/7400" {
		t.Errorf("got %v, want the detected set untouched", got)
	}
}

// TestAnnounceReplacesRatherThanAppends is the point. These addresses end up in the RelayHints of
// every record this node provisions, and a sender tries each in turn — so leaving the private one
// alongside the public one costs every sender a timeout before mail gets through.
func TestAnnounceReplacesRatherThanAppends(t *testing.T) {
	detected := mas(t, "/ip4/127.0.0.1/tcp/7400", "/ip4/10.0.0.5/tcp/7400")
	got := announceFactory([]string{"/ip4/203.0.113.7/tcp/7400"})(detected)
	if len(got) != 1 {
		t.Fatalf("got %v, want only the announced address", got)
	}
	if got[0].String() != "/ip4/203.0.113.7/tcp/7400" {
		t.Errorf("got %s", got[0])
	}
}

// TestAnnounceIgnoresJunkRatherThanFailing: a typo must not leave the node announcing nothing,
// which would make it undiscoverable — a worse failure than announcing an imperfect address, and
// a much harder one to diagnose.
func TestAnnounceIgnoresJunkRatherThanFailing(t *testing.T) {
	detected := mas(t, "/ip4/10.0.0.5/tcp/7400")

	got := announceFactory([]string{"not-a-multiaddr"})(detected)
	if len(got) != 1 || got[0].String() != "/ip4/10.0.0.5/tcp/7400" {
		t.Errorf("an unparseable override left the node announcing %v; want the detected set", got)
	}
	// A good entry alongside a bad one still applies.
	got = announceFactory([]string{"nonsense", "/ip4/203.0.113.7/tcp/7400", "  "})(detected)
	if len(got) != 1 || got[0].String() != "/ip4/203.0.113.7/tcp/7400" {
		t.Errorf("got %v, want just the valid override", got)
	}
}
