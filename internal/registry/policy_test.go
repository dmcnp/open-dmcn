package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestAddressUsablePolicy exercises the relay FETCH-path validity gate: on a
// require-countersign domain an uncountersigned address is pending and a
// countersigned one is usable; domains without the policy (or without a DAR) are
// always usable.
func TestAddressUsablePolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	reg, src := makeReg(t)

	root := mustKP(t)

	// Managed domain that REQUIRES countersignature.
	darReq, _ := identity.NewDomainAuthorityRecord("managed.me", root, time.Now())
	darReq.PolicyFlags |= identity.PolicyRequireCountersign
	if err := darReq.Sign(root); err != nil {
		t.Fatal(err)
	}
	src.PutDAR(darReq)

	// Managed domain that does NOT require countersignature.
	darOpen, _ := identity.NewDomainAuthorityRecord("open.me", root, time.Now())
	if err := darOpen.Sign(root); err != nil {
		t.Fatal(err)
	}
	src.PutDAR(darOpen)

	// Uncountersigned address on the require domain → pending.
	pending := uncredentialedIdentity(t, "alice@managed.me", mustKP(t))
	if err := reg.AddressUsable(ctx, pending); !errors.Is(err, ErrPendingCountersign) {
		t.Fatalf("uncountersigned on require domain: got %v, want ErrPendingCountersign", err)
	}

	// Countersigned address on the require domain → usable.
	usable := credentialedIdentity(t, "bob@managed.me", mustKP(t), root)
	if err := reg.AddressUsable(ctx, usable); err != nil {
		t.Fatalf("countersigned on require domain: got %v, want usable", err)
	}

	// Uncountersigned address on a domain without the require bit → usable.
	open := uncredentialedIdentity(t, "carol@open.me", mustKP(t))
	if err := reg.AddressUsable(ctx, open); err != nil {
		t.Fatalf("uncountersigned on open domain: got %v, want usable", err)
	}

	// Uncountersigned address on a domain with NO DAR → usable.
	nodar := uncredentialedIdentity(t, "dave@nodar.me", mustKP(t))
	if err := reg.AddressUsable(ctx, nodar); err != nil {
		t.Fatalf("uncountersigned on no-DAR domain: got %v, want usable", err)
	}
}
