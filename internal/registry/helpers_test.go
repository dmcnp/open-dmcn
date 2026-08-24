package registry

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// memSource is an in-memory RecordSource for tests: verification reads its
// DARs/records/removals/blocklists from these maps (they stub the fleet resolver).
type memSource struct {
	dars     map[string]*identity.DomainAuthorityRecord
	recs     map[string]*identity.IdentityRecord
	removals map[string]*identity.AddressRemovalRecord
	blocks   map[string]*identity.CredentialBlockList
}

func newMemSource() *memSource {
	return &memSource{
		dars:     map[string]*identity.DomainAuthorityRecord{},
		recs:     map[string]*identity.IdentityRecord{},
		removals: map[string]*identity.AddressRemovalRecord{},
		blocks:   map[string]*identity.CredentialBlockList{},
	}
}

func (m *memSource) PutDAR(d *identity.DomainAuthorityRecord)     { m.dars[d.Domain] = d }
func (m *memSource) PutIdentity(r *identity.IdentityRecord)       { m.recs[r.Address] = r }
func (m *memSource) PutRemoval(r *identity.AddressRemovalRecord)  { m.removals[r.Address] = r }
func (m *memSource) PutBlocklist(b *identity.CredentialBlockList) { m.blocks[b.Domain] = b }

func (m *memSource) source() *RecordSource {
	return &RecordSource{
		Identity: func(_ context.Context, a string) (*identity.IdentityRecord, error) {
			if r, ok := m.recs[a]; ok {
				return r, nil
			}
			return nil, fmt.Errorf("%w: %s", ErrNotFound, a)
		},
		DAR: func(_ context.Context, d string) (*identity.DomainAuthorityRecord, error) {
			if r, ok := m.dars[d]; ok {
				return r, nil
			}
			return nil, fmt.Errorf("%w: %s", ErrNotFound, d)
		},
		Removal:   func(_ context.Context, a string) (*identity.AddressRemovalRecord, error) { return m.removals[a], nil },
		Blocklist: func(_ context.Context, d string) (*identity.CredentialBlockList, error) { return m.blocks[d], nil },
	}
}

// makeReg returns a verification registry backed by an in-memory source (okDNS anchor) plus
// the source so a test can populate the DARs/records/removals it verifies against.
func makeReg(t *testing.T) (*Registry, *memSource) {
	t.Helper()
	src := newMemSource()
	reg := New(WithDNSVerifier(okDNS))
	reg.SetRecordSource(src.source())
	return reg, src
}

func mustKP(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func okDNS(context.Context, string, string) error { return nil }
func mismatchDNS(context.Context, string, string) error {
	return domainverify.ErrFingerprintMismatch
}
func errorDNS(context.Context, string, string) error { return errors.New("dns timeout") }

// uncredentialedIdentity builds a self-signed record with no domain address credential.
func uncredentialedIdentity(t *testing.T, address string, kp *identity.IdentityKeyPair) *identity.IdentityRecord {
	t.Helper()
	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	return rec
}

// credentialedIdentity builds a self-signed record with a domain-issued address credential.
func credentialedIdentity(t *testing.T, address string, user, signer *identity.IdentityKeyPair) *identity.IdentityRecord {
	t.Helper()
	rec, err := identity.NewIdentityRecord(address, user)
	if err != nil {
		t.Fatal(err)
	}
	rec.RelayHints = []string{"/ip4/127.0.0.1/tcp/7400/p2p/test"}
	rec.VerificationTier = identity.TierDomainDNS
	if err := rec.Sign(user); err != nil {
		t.Fatal(err)
	}
	if err := rec.IssueAddressCredential(signer, time.Now()); err != nil {
		t.Fatal(err)
	}
	return rec
}
