package node_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/relay"
)

// A node anchors a domain's FIRST DAR in its own _dmcn view — the static map here, read exactly as
// the resolver reads it — and refuses a first DAR whose fingerprint the domain does not publish.
// Also pins the late binding: the map is installed AFTER New returns and the anchor still sees it.
func TestGenesisDARAnchoredThroughNodeStaticDNS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0",
		DataDir: t.TempDir(), Mailbox: true,
	})
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	defer n.Close()

	good := signDAR(t, "anchored.example", mustKPT(t))
	bad := signDAR(t, "unanchored.example", mustKPT(t))
	n.SetStaticDNS(map[string]domainverify.Record{
		"anchored.example":   {Fingerprint: good.Fingerprint()},
		"unanchored.example": {Fingerprint: "0000000000000000000000000000000000000000"},
	})
	accept := func(dar *identity.DomainAuthorityRecord) (bool, string) {
		t.Helper()
		data, err := proto.Marshal(dar.ToProto())
		if err != nil {
			t.Fatal(err)
		}
		return n.Relay().AcceptRecord(ctx, dmcnpb.RecordKind_RECORD_KIND_DAR, data)
	}

	if ok, reason := accept(good); !ok {
		t.Fatalf("anchored genesis DAR refused: %s", reason)
	}
	if stored, _ := n.Records().GetDAR(ctx, "anchored.example"); stored == nil {
		t.Fatal("anchored DAR not stored")
	}
	ok, reason := accept(bad)
	if ok {
		t.Fatal("genesis DAR accepted although _dmcn publishes a different fingerprint")
	}
	if !strings.HasPrefix(reason, relay.ReasonDARNotAnchored) {
		t.Fatalf("wrong reason: %s", reason)
	}
	if stored, _ := n.Records().GetDAR(ctx, "unanchored.example"); stored != nil {
		t.Fatal("unanchored DAR stored")
	}
}
