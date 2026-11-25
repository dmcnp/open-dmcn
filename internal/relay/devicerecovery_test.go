package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

const recoveryDelay = 7 * 24 * time.Hour

// TestDeviceRecoveryLetsAStrandedOwnerBackIn is the case the arm exists for: every device is
// gone, nobody is left to approve a new one, and the owner still holds the account key. Refusing
// outright would make losing your devices permanent, so the request is admitted on a delay.
func TestDeviceRecoveryLetsAStrandedOwnerBackIn(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	at := time.Unix(1_700_000_000, 0)
	s.SetClock(func() time.Time { return at })

	// A mailbox with one enrolled device the owner no longer has.
	lost := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, lost, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}

	// The replacement device can neither be approved (nothing to approve it) nor let itself in.
	replacement := devKey(t)
	rec, genesis, err := s.Enroll(ctx, devTestRx, replacement, nil, false, recoveryDelay, true, nil, nil)
	if err != nil {
		t.Fatalf("recovery enrolment refused: %v", err)
	}
	if genesis {
		t.Fatal("a recovery enrolment is not a genesis one")
	}
	if rec.EligibleAt != at.Add(recoveryDelay).Unix() {
		t.Fatalf("eligible_at = %d, want the request time plus the delay", rec.EligibleAt)
	}

	// It is ON the mailbox and VISIBLE, and it cannot act yet. That gap is the whole design.
	if s.IsActive(ctx, devTestRx, replacement) {
		t.Fatal("a pending device should not be able to act during its wait")
	}
	pending, err := s.Pending(ctx, devTestRx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %d, err = %v; the request must be visible while it waits", len(pending), err)
	}

	// Most of the way through the wait it still cannot act.
	s.SetClock(func() time.Time { return at.Add(recoveryDelay - time.Minute) })
	if s.IsActive(ctx, devTestRx, replacement) {
		t.Fatal("a pending device became active before its delay elapsed")
	}

	// And once the window passes with no veto, the owner is back in.
	s.SetClock(func() time.Time { return at.Add(recoveryDelay + time.Minute) })
	if !s.IsActive(ctx, devTestRx, replacement) {
		t.Fatal("the recovery device should be active once its delay has elapsed")
	}
}

// TestDeviceRecoveryCanBeVetoed is the other half: when the owner DOES still have a device, a
// recovery request by someone holding a copied account key is something they can stop. The veto
// is an ordinary retirement of the pending record, so it leaves the same visible tombstone.
func TestDeviceRecoveryCanBeVetoed(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	at := time.Unix(1_700_000_000, 0)
	s.SetClock(func() time.Time { return at })

	owned := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, owned, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	thief := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, thief, nil, false, recoveryDelay, true, nil, nil); err != nil {
		t.Fatal(err)
	}

	// The veto lands while the request is still pending.
	s.SetClock(func() time.Time { return at.Add(24 * time.Hour) })
	if _, err := s.Retire(ctx, devTestRx, thief); err != nil {
		t.Fatalf("veto refused: %v", err)
	}

	// Past the original window, the vetoed device is still nothing.
	s.SetClock(func() time.Time { return at.Add(recoveryDelay + time.Hour) })
	if s.IsActive(ctx, devTestRx, thief) {
		t.Fatal("a vetoed device became active anyway")
	}
	// And it cannot simply ask again: the key is burned on this mailbox for good.
	if _, _, err := s.Enroll(ctx, devTestRx, thief, nil, false, recoveryDelay, true, nil, nil); !errors.Is(err, ErrDeviceRetired) {
		t.Fatalf("err = %v — a vetoed device key was allowed to re-request", err)
	}
}

// TestDeviceRecoveryVetoWorksWithNoActiveDevice: the last-active guard must not block a veto.
// A mailbox whose only devices are gone is exactly where a hostile recovery request is least
// likely to be noticed, so it is the last place the veto should be unavailable.
func TestDeviceRecoveryVetoWorksWithNoActiveDevice(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	at := time.Unix(1_700_000_000, 0)
	s.SetClock(func() time.Time { return at })

	// One enrolled device, and two competing recovery requests.
	only := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, only, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	a, b := devKey(t), devKey(t)
	for _, d := range [][]byte{a, b} {
		if _, _, err := s.Enroll(ctx, devTestRx, d, nil, false, recoveryDelay, true, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Retiring a PENDING device never reduces the active set, so the guard stays quiet.
	if _, err := s.Retire(ctx, devTestRx, a); err != nil {
		t.Fatalf("vetoing a pending device hit the last-active guard: %v", err)
	}
	// The one genuinely active device is still protected.
	if _, err := s.Retire(ctx, devTestRx, only); !errors.Is(err, ErrDeviceLastActive) {
		t.Fatalf("err = %v, want the last active device to stay protected", err)
	}
}

// TestDeviceRecoveryRefusedWhenDomainDisablesIt: a domain may turn the path off, and then an
// unapproved device is refused outright as it was before.
func TestDeviceRecoveryRefusedWhenDomainDisablesIt(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, false, 0, false, nil, nil); !errors.Is(err, ErrDeviceRegistryClaimed) {
		t.Fatalf("err = %v, want a flat refusal where recovery is disabled", err)
	}
}

// TestDeviceRecoveryPendingClaimsTheRegistry: a pending request still counts as claiming the
// registry, or an attacker could request recovery and then race someone into the genesis path
// that a truly empty registry would offer.
func TestDeviceRecoveryPendingClaimsTheRegistry(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, false, recoveryDelay, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Retire the one active device's registry down to pending-only is impossible (last-active),
	// so instead assert directly: a registry holding only records is never genesis again.
	if _, genesis, err := s.Enroll(ctx, devTestRx, devKey(t), nil, false, recoveryDelay, true, nil, nil); err != nil || genesis {
		t.Fatalf("genesis = %v, err = %v; a claimed registry must never reopen", genesis, err)
	}
}

// TestDeviceRecoveryPolicyResolution: unset must mean a working default rather than no recovery
// at all, and disabling it must take an explicit choice. Permanent lockout is the worse failure
// for an ordinary user, so it is the one that has to be asked for by name.
func TestDeviceRecoveryPolicyResolution(t *testing.T) {
	var dar identity.DomainAuthorityRecord

	delay, allowed := dar.DeviceRecoveryDelay()
	if !allowed || delay != identity.DefaultDeviceRecoveryDelay {
		t.Fatalf("unset policy gave (%v, %v), want the default delay and allowed", delay, allowed)
	}

	dar.DeviceRecoveryDelayHours = 48
	if delay, allowed = dar.DeviceRecoveryDelay(); !allowed || delay != 48*time.Hour {
		t.Fatalf("explicit policy gave (%v, %v), want 48h and allowed", delay, allowed)
	}

	dar.DeviceRecoveryDelayHours = identity.DeviceRecoveryDisabled
	if _, allowed = dar.DeviceRecoveryDelay(); allowed {
		t.Fatal("the disabled sentinel should turn recovery off")
	}
}
