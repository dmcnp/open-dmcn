package registry

import (
	"context"
	"errors"
	"testing"
	"time"


	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestAddressReserved checks the web registration gate resolver: true only when the address's
// local-part is in its domain DAR's reserved list; false for an unlisted name or a domain with no
// DAR. It also checks the AddressUsable refinement: a reserved local-part requires the domain
// authority's countersignature to be usable even on a domain that does not RequireCountersign.
func TestAddressReserved(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	reg, src := makeReg(t)

	root := mustKP(t)
	// An OPEN domain (no RequireCountersign) that nonetheless reserves "press".
	dar, _ := identity.NewDomainAuthorityRecord("res.test", root, time.Now())
	dar.AuthorityEffectiveFrom = time.Now().Add(-time.Hour)
	dar.ReservedLocalParts = []string{"press"}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	src.PutDAR(dar)
	time.Sleep(300 * time.Millisecond)

	if !reg.AddressReserved(ctx, "press@res.test") {
		t.Error("press@res.test should be reserved")
	}
	if reg.AddressReserved(ctx, "PRESS@res.test") == false {
		t.Error("reserved match should be case-insensitive")
	}
	if reg.AddressReserved(ctx, "alice@res.test") {
		t.Error("alice@res.test (unlisted) should not be reserved")
	}
	if reg.AddressReserved(ctx, "postmaster@res.test") {
		t.Error("postmaster@res.test (unlisted, no baseline floor) should not be reserved")
	}
	if reg.AddressReserved(ctx, "press@nodar.test") {
		t.Error("a domain with no DAR must reserve nothing")
	}

	// AddressUsable: a reserved, uncountersigned record is pending even though the domain is open.
	pending := uncredentialedIdentity(t, "press@res.test", mustKP(t))
	if err := reg.AddressUsable(ctx, pending); !errors.Is(err, ErrPendingCountersign) {
		t.Fatalf("reserved uncountersigned: got %v, want ErrPendingCountersign", err)
	}
	// A non-reserved address on the same open domain stays usable without a countersignature.
	open := uncredentialedIdentity(t, "alice@res.test", mustKP(t))
	if err := reg.AddressUsable(ctx, open); err != nil {
		t.Fatalf("unreserved on open domain: got %v, want usable", err)
	}
	// Once the domain authority countersigns the reserved address, it becomes usable.
	approved := credentialedIdentity(t, "press@res.test", mustKP(t), root)
	if err := reg.AddressUsable(ctx, approved); err != nil {
		t.Fatalf("countersigned reserved address: got %v, want usable", err)
	}
}
