package relay

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

const genesisDomain = "served.example"

// genesisFixture is a relay that holds NO DAR yet with a switchable DNS anchor — the position a
// domain's FIRST DAR arrives at. The genesis write has no prior root to chain to, so the anchor is
// all that stands between an admitted peer and installing the root key every later check trusts.
type genesisFixture struct {
	relay       *Relay
	anchorErr   error
	anchorCalls int
}

func newGenesisFixture(t *testing.T) *genesisFixture {
	t.Helper()
	h := newTestHost(t)
	t.Cleanup(func() { h.Close() })
	f := &genesisFixture{}
	f.relay = New(h, nfLookup, WithRecordStore(newRecords(t)),
		WithDARAnchor(func(context.Context, string, string) error {
			f.anchorCalls++
			return f.anchorErr
		}))
	return f
}

func genesisDAR(t *testing.T, domain string) (*identity.DomainAuthorityRecord, *identity.IdentityKeyPair) {
	t.Helper()
	root, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dar, err := identity.NewDomainAuthorityRecord(domain, root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	return dar, root
}

func (f *genesisFixture) accept(t *testing.T, dar *identity.DomainAuthorityRecord) (bool, string) {
	t.Helper()
	data, err := proto.Marshal(dar.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	return f.relay.AcceptRecord(context.Background(), dmcnpb.RecordKind_RECORD_KIND_DAR, data)
}

// A first DAR whose fingerprint the domain does not publish in _dmcn is refused and NOT stored:
// the anchor is what makes the first root the domain owner's rather than whoever pushed first.
func TestGenesisDARRefusedWithoutDNSAnchor(t *testing.T) {
	f := newGenesisFixture(t)
	f.anchorErr = errors.New("NXDOMAIN")
	dar, _ := genesisDAR(t, genesisDomain)

	ok, reason := f.accept(t, dar)
	if ok {
		t.Fatal("unanchored genesis DAR accepted")
	}
	if !strings.HasPrefix(reason, ReasonDARNotAnchored) {
		t.Fatalf("wrong reason: %s", reason)
	}
	if f.anchorCalls != 1 {
		t.Fatalf("anchor consulted %d times, want 1", f.anchorCalls)
	}
	if stored, _ := f.relay.records.GetDAR(context.Background(), genesisDomain); stored != nil {
		t.Fatal("refused DAR was stored anyway")
	}
}

func TestGenesisDARAcceptedWhenAnchored(t *testing.T) {
	f := newGenesisFixture(t)
	dar, _ := genesisDAR(t, genesisDomain)

	if ok, reason := f.accept(t, dar); !ok {
		t.Fatalf("anchored genesis DAR refused: %s", reason)
	}
	stored, err := f.relay.records.GetDAR(context.Background(), genesisDomain)
	if err != nil || stored == nil {
		t.Fatalf("DAR not stored: %v", err)
	}
	if stored.Fingerprint() != dar.Fingerprint() {
		t.Fatal("stored DAR is not the accepted one")
	}
}

// Once a DAR is on file, later DARs are admitted by root-key continuity alone (no DNS): a
// rotation that supersedes the trusted root goes through even when DNS is unreachable, so a DNS
// outage can never block a domain from rotating its key.
func TestDARRotationDoesNotConsultAnchor(t *testing.T) {
	f := newGenesisFixture(t)
	dar, root := genesisDAR(t, genesisDomain)
	if ok, reason := f.accept(t, dar); !ok {
		t.Fatalf("genesis: %s", reason)
	}
	f.anchorErr = errors.New("DNS down")

	newRoot, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := identity.NewDomainAuthorityRecord(genesisDomain, newRoot, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rotated.Revision = dar.Revision + 1
	rotated.SupersededKeys = append(rotated.SupersededKeys, identity.AuthorityKey{
		Ed25519Public: root.Ed25519Public,
		X25519Public:  root.X25519Public,
		EffectiveFrom: root.CreatedAt.UTC(),
	})
	if err := rotated.Sign(newRoot); err != nil {
		t.Fatal(err)
	}
	if ok, reason := f.accept(t, rotated); !ok {
		t.Fatalf("rotation refused while DNS is down: %s", reason)
	}
	if f.anchorCalls != 1 {
		t.Fatalf("anchor consulted on the continuity path (%d calls, want 1 from genesis)", f.anchorCalls)
	}
}
