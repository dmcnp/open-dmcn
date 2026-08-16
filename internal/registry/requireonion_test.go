package registry

import (
	"context"
	"testing"
	"time"


	"dmcn.dev/open-dmcn/internal/core/identity"
)

// RequiresOnion is the effective policy: the mailbox's own flag OR its domain's
// DAR PolicyRequireOnion (stricter-wins).
func TestRegistryRequiresOnion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	reg, src := makeReg(t)

	root := mustKP(t)

	// Domain that mandates onion for all its addresses.
	darOnion, _ := identity.NewDomainAuthorityRecord("onion.me", root, time.Now())
	darOnion.PolicyFlags |= identity.PolicyRequireOnion
	if err := darOnion.Sign(root); err != nil {
		t.Fatal(err)
	}
	src.PutDAR(darOnion)

	// Domain with a DAR but no onion mandate.
	darOpen, _ := identity.NewDomainAuthorityRecord("open.me", root, time.Now())
	if err := darOpen.Sign(root); err != nil {
		t.Fatal(err)
	}
	src.PutDAR(darOpen)
	time.Sleep(300 * time.Millisecond)

	cases := []struct {
		name string
		rec  *identity.IdentityRecord
		want bool
	}{
		{"domain mandate forces onion", &identity.IdentityRecord{Address: "alice@onion.me"}, true},
		{"mailbox flag forces onion on open domain", &identity.IdentityRecord{Address: "bob@open.me", RequireOnion: true}, true},
		{"open domain, no flag", &identity.IdentityRecord{Address: "carol@open.me"}, false},
		{"no DAR, no flag", &identity.IdentityRecord{Address: "dave@nodar.me"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reg.RequiresOnion(ctx, tc.rec); got != tc.want {
				t.Fatalf("RequiresOnion = %v, want %v", got, tc.want)
			}
		})
	}
}
