package relay

import (
	"context"
	"fmt"
	"testing"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// Shared test helpers (originally in drain_test.go, which was dropped with the
// operator/drain surface). Kept for the surviving core tests.

func nfLookup(_ context.Context, _ string) (*identity.IdentityRecord, error) {
	return nil, fmt.Errorf("not found")
}

func newMailbox(t *testing.T) *MailboxStore {
	t.Helper()
	d := openMailboxDS(t, t.TempDir())
	t.Cleanup(func() { d.Close() })
	return NewMailboxStore(d)
}

func newAccounts(t *testing.T) *AccountStore {
	t.Helper()
	d := openMailboxDS(t, t.TempDir())
	t.Cleanup(func() { d.Close() })
	as, err := NewAccountStore(d, []byte("node-secret-for-tests-1234567890"))
	if err != nil {
		t.Fatal(err)
	}
	return as
}
