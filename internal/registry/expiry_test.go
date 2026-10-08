package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

func expiringRecord(t *testing.T, at time.Time) *identity.IdentityRecord {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord("alice@dmcn.email", kp)
	if err != nil {
		t.Fatal(err)
	}
	rec.ExpiresAt = at
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestLookupTreatsAnExpiredRecordAsAbsent: a node that still holds an expired record must not bring
// it back to life for a reader. Senders and the bridge resolve through here, so this is what makes
// an expired address unreachable.
func TestLookupTreatsAnExpiredRecordAsAbsent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		at      time.Time
		present bool
	}{
		{"no expiry", time.Time{}, true},
		{"not yet", time.Now().Add(time.Hour), true},
		{"expired", time.Now().Add(-time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := expiringRecord(t, tc.at)
			reg := New()
			reg.SetRecordSource(&RecordSource{Identity: func(context.Context, string) (*identity.IdentityRecord, error) {
				return rec, nil
			}})
			got, err := reg.Lookup(context.Background(), rec.Address)
			if tc.present {
				if err != nil || got == nil {
					t.Fatalf("Lookup = (%v, %v), want the record", got, err)
				}
				return
			}
			if got != nil || !errors.Is(err, ErrNotFound) {
				t.Fatalf("Lookup = (%v, %v), want ErrNotFound", got, err)
			}
		})
	}
}

// TestVerifyRefusesAnExpiredRecord: a record can also reach a verifier without a lookup, so
// verification refuses it on its own account.
func TestVerifyRefusesAnExpiredRecord(t *testing.T) {
	rec := expiringRecord(t, time.Now().Add(-time.Second))
	tier, err := New().VerifyManagedIdentity(context.Background(), rec)
	if err == nil || tier != identity.TierUnverified {
		t.Fatalf("VerifyManagedIdentity(expired) = (%v, %v), want unverified with an error", tier, err)
	}
}
